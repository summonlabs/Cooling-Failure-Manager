// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_COOLING_FAILURE_MANAGER_ENUMS_HPP
#define DCCP_COOLING_FAILURE_MANAGER_ENUMS_HPP

#include <cstdint>
#include <string>
#include <string_view>

#include "dccp/cooling_failure_manager/result.hpp"

namespace dccp::cooling_failure_manager {

/// Every enumeration in this header has a stable lowercase canonical token.
/// Tokens are part of the durable format and of the public contract: an existing
/// token is never renamed or repurposed. Decoding is strict - an unknown token
/// is rejected with UnknownEnumToken, never mapped onto a default value, because
/// silently degrading an unknown failure class or an unknown freshness state
/// into a known one is exactly the class of defect this library exists to
/// prevent.

// ---------------------------------------------------------------------------
// Availability of an observation
// ---------------------------------------------------------------------------

/// Availability of one observed quantity.
///
/// This is the central anti-inference rule of the whole component: a reading
/// that was never produced is Indeterminate, which is *not* Healthy and *not*
/// zero. There is no implicit conversion from Indeterminate to any healthy or
/// zero-valued state anywhere in the public API.
enum class Availability : std::uint8_t {
  Indeterminate = 0,  ///< no usable reading exists; never treated as healthy or zero
  Observed = 1,       ///< a reading exists and its quality is reported separately
};

std::string_view to_token(Availability value) noexcept;
Result<Availability> availability_from_token(std::string_view token);

/// Quality of an observation that exists, as reported by its producer.
enum class ObservationQuality : std::uint8_t {
  Good = 0,
  Degraded = 1,
  Suspect = 2,
  Bad = 3,
};

std::string_view to_token(ObservationQuality value) noexcept;
Result<ObservationQuality> observation_quality_from_token(std::string_view token);

/// Freshness of evidence relative to the decision clock.
///
/// Unobserved is distinct from Stale: "nobody ever told me" and "the last thing
/// I was told has aged out" are different facts with different explanations and
/// different recovery consequences.
enum class Freshness : std::uint8_t {
  Unobserved = 0,  ///< no observation has ever been recorded for this subject
  Stale = 1,       ///< an observation exists but its age exceeds the window
  Current = 2,     ///< an observation exists and is within the window
  Future = 3,      ///< the observation is dated after the decision clock
};

std::string_view to_token(Freshness value) noexcept;
Result<Freshness> freshness_from_token(std::string_view token);

/// Confirmation state of one cooling failure class for one scope.
///
/// Suspected and Confirmed are both non-healthy. Contradicted and Unsupported
/// are non-healthy too: "we have evidence against it" and "we have no evidence
/// either way" are never collapsed into absence of failure. Only Healthy means
/// the evidence positively supports normal cooling for that class.
enum class ConfirmationState : std::uint8_t {
  Unknown = 0,        ///< no usable evidence for this class
  Healthy = 1,        ///< usable evidence positively supports normal cooling
  Suspected = 2,      ///< evidence is consistent with failure but not sufficient
  Confirmed = 3,      ///< evidence satisfies the class's confirmation demand
  Contradicted = 4,   ///< usable evidence argues against failure
  Unsupported = 5,    ///< the class cannot be evidenced with the declared inputs
};

std::string_view to_token(ConfirmationState value) noexcept;
Result<ConfirmationState> confirmation_state_from_token(std::string_view token);

// ---------------------------------------------------------------------------
// Cooling failure classification
// ---------------------------------------------------------------------------

/// The cooling failure classes this component owns.
///
/// The list is closed: a producer cannot invent a new class, which keeps
/// classification, response eligibility and recovery gates in one taxonomy.
enum class FailureClass : std::uint8_t {
  PlantLoss = 0,             ///< chiller / heat-rejection plant loss
  PumpFailure = 1,           ///< pump stop, dead-head or loss of pumping
  LoopDegradation = 2,       ///< partial loop degradation without loss
  LoopLoss = 3,              ///< total loss of a cooling loop
  ChillerFailure = 4,        ///< one chiller unit failed inside a live plant
  CduFailure = 5,            ///< coolant distribution unit failure
  ValveFlowFailure = 6,      ///< valve, flow or differential-pressure failure
  PressureFailure = 7,       ///< loop pressure outside its service envelope
  CrahCracFailure = 8,       ///< CRAH/CRAC unit failure
  AirflowLoss = 9,           ///< loss of airflow without a unit failure
  ContainmentBreach = 10,    ///< containment breach (hot/cold aisle, plenum)
  Leak = 11,                 ///< coolant leak evidence
  ThermalCapacityLoss = 12,  ///< measured thermal capacity below demand
  SharedSourceFailure = 13,  ///< failure of a plant/loop shared by several scopes
  ThermalRunaway = 14,       ///< diverging temperature despite available capacity
};

std::string_view to_token(FailureClass value) noexcept;
Result<FailureClass> failure_class_from_token(std::string_view token);

/// Every class, in canonical order. Used to iterate deterministically.
const FailureClass* failure_class_order() noexcept;
std::size_t failure_class_count() noexcept;

/// True when the class is a loss of the whole cooling function of a scope rather
/// than a degradation of it.
///
/// This predicate decides which confirmed upstream failures are attributed to the
/// scopes that depend on them, so it is deliberately narrow: a single failed
/// chiller unit, a single failed air-handling unit, a failed pump set, a
/// containment breach, a leak and a capacity shortfall are all degradations of a
/// still-functioning scope, and attributing any of them downstream would report a
/// loss that did not happen. Used by the decision engine, never by a caller to
/// bypass the decision engine.
bool failure_class_is_total_loss(FailureClass value) noexcept;

/// Impact of a confirmed failure on the affected scope's cooling function.
enum class Severity : std::uint8_t {
  None = 0,
  Degraded = 1,
  Impaired = 2,
  Critical = 3,
  Total = 4,
};

std::string_view to_token(Severity value) noexcept;
Result<Severity> severity_from_token(std::string_view token);

bool severity_at_least(Severity value, Severity floor) noexcept;

/// How quickly the affected scope is expected to exhaust its thermal capacity.
enum class Urgency : std::uint8_t {
  Routine = 0,
  Elevated = 1,
  Imminent = 2,
  Immediate = 3,
};

std::string_view to_token(Urgency value) noexcept;
Result<Urgency> urgency_from_token(std::string_view token);

bool urgency_at_least(Urgency value, Urgency floor) noexcept;

/// Interval in which the affected scope can hold its thermal load. Reported as a
/// bounded duration; Zero means "no holding time observed", not "unknown".
enum class TimeToImpact : std::uint8_t {
  Unobserved = 0,
  Zero = 1,
  Minutes = 2,
  TensOfMinutes = 3,
  Hours = 4,
  Days = 5,
};

std::string_view to_token(TimeToImpact value) noexcept;
Result<TimeToImpact> time_to_impact_from_token(std::string_view token);

// ---------------------------------------------------------------------------
// Evidence and observation channels
// ---------------------------------------------------------------------------

/// Channel a cooling observation was produced on. Recorded so contradictory
/// evidence can be reported as a disagreement between named channels rather than
/// silently averaged.
enum class ObservationChannel : std::uint8_t {
  FlowMeter = 0,
  DifferentialPressure = 1,
  AbsolutePressure = 2,
  CoolantTemperature = 3,
  AirTemperature = 4,
  LeakDetector = 5,
  PumpStatus = 6,
  ValvePosition = 7,
  ChillerStatus = 8,
  CduStatus = 9,
  CrahCracStatus = 10,
  AirflowMeter = 11,
  ContainmentSwitch = 12,
  ThermalCapacityMeter = 13,
  ThermalLoadMeter = 14,
  ThermalMarginMeter = 15,
  HumiditySensor = 16,
};

std::string_view to_token(ObservationChannel value) noexcept;
Result<ObservationChannel> observation_channel_from_token(std::string_view token);

const ObservationChannel* observation_channel_order() noexcept;
std::size_t observation_channel_count() noexcept;

/// Leak evidence state.
///
/// LeakNone is produced only by an observation that positively reports no leak.
/// A missing leak observation is LeakUnknown, and LeakUnknown never satisfies a
/// recovery gate.
enum class LeakState : std::uint8_t {
  LeakUnknown = 0,    ///< no leak observation
  LeakNone = 1,       ///< positively no leak
  LeakSuspected = 2,  ///< moisture or a slow loss without a located breach
  LeakConfirmed = 3,  ///< a located or instrumented breach
  LeakActive = 4,     ///< breach with ongoing loss
};

std::string_view to_token(LeakState value) noexcept;
Result<LeakState> leak_state_from_token(std::string_view token);

/// True when the leak state positively asserts that no coolant is escaping.
bool leak_state_is_clear(LeakState value) noexcept;

// ---------------------------------------------------------------------------
// Evidence status of one already-recorded observation
// ---------------------------------------------------------------------------

/// Why an observation may or may not be used as current evidence.
///
/// Every value other than Current forbids the observation from satisfying a
/// recovery gate or a failure confirmation.
enum class EvidenceStatus : std::uint8_t {
  Current = 0,
  Missing = 1,             ///< no observation recorded for the subject
  Stale = 2,               ///< recorded, but older than the evidence window
  Conflicting = 3,         ///< two channels of equal standing disagree
  OutOfOrder = 4,          ///< a lower sequence arrived after a higher one
  Unbound = 5,             ///< the observation carries no evidence generation
  Indeterminate = 6,       ///< recorded but unusable (quality Bad, or gap in the reading)
  Future = 7,              ///< dated after the decision clock
};

std::string_view to_token(EvidenceStatus value) noexcept;
Result<EvidenceStatus> evidence_status_from_token(std::string_view token);

bool evidence_status_is_usable(EvidenceStatus value) noexcept;

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

/// Cooling mitigations this component may request from Adjacent owners.
///
/// This enumeration names *requests*. Accepting a request is not proof that
/// coolant moved, that airflow resumed or that thermal capacity recovered; that
/// requires separate verified effect evidence.
enum class ResponseAction : std::uint8_t {
  ObserveOnly = 0,             ///< hold, gather evidence, change nothing
  VerifyEvidence = 1,          ///< solicit a fresh observation on a named channel
  IsolateScope = 2,            ///< request isolation of the affected scope
  FailoverCoolingSource = 3,   ///< request source selection by the failover owner
  StartStandbyPump = 4,        ///< request a standby pump start
  StartStandbyChiller = 5,     ///< request a standby chiller start
  OpenBypassValve = 6,         ///< request bypass flow
  CloseIsolationValve = 7,     ///< request isolation valve closure
  RaiseFanSpeed = 8,           ///< request increased air movement
  ReduceThermalLoad = 9,       ///< request reduced heat rejection demand
  ThrottleWorkload = 10,       ///< request workload throttling (placed by its owner)
  EvacuateScope = 11,          ///< request evacuation of the scope
  EmergencyShutdown = 12,      ///< request emergency shutdown of the scope
  ManualIntervention = 13,     ///< request a human operator
};

std::string_view to_token(ResponseAction value) noexcept;
Result<ResponseAction> response_action_from_token(std::string_view token);

const ResponseAction* response_action_order() noexcept;
std::size_t response_action_count() noexcept;

/// True when the action can only reduce load rather than restore cooling.
bool response_action_is_load_reduction(ResponseAction value) noexcept;

/// True when the action is a protective restriction rather than a recovery
/// attempt.
bool response_action_is_protective(ResponseAction value) noexcept;

/// What kind of evidence would prove that an action had its intended cooling
/// effect.
enum class EffectClass : std::uint8_t {
  None = 0,
  FlowRestored = 1,
  PressureRestored = 2,
  TemperatureContained = 3,
  ThermalCapacityRestored = 4,
  LeakContained = 5,
  ContainmentRestored = 6,
  LoadReduced = 7,
};

std::string_view to_token(EffectClass value) noexcept;
Result<EffectClass> effect_class_from_token(std::string_view token);

/// Lifecycle of one response plan.
///
/// The plan records what this component decided. It never records what an
/// adjacent owner did with the request as though that were this component's
/// state.
enum class PlanLifecycle : std::uint8_t {
  Unplanned = 0,
  Planned = 1,        ///< eligibility computed, nothing solicited yet
  Solicited = 2,      ///< a bounded request was issued
  Active = 3,         ///< a response is in progress
  Stabilized = 4,     ///< protective restrictions hold the scope; recovering
  Recovering = 5,     ///< recovery gates are being evaluated
  Recovered = 6,      ///< every recovery gate passed on current evidence
  Withdrawn = 7,      ///< the failure was retracted; the plan is void
};

std::string_view to_token(PlanLifecycle value) noexcept;
Result<PlanLifecycle> plan_lifecycle_from_token(std::string_view token);

/// Lifecycle of one solicited attempt.
enum class AttemptState : std::uint8_t {
  Planned = 0,       ///< created, not yet solicited
  Solicited = 1,     ///< request issued; no reply recorded
  Acknowledged = 2,  ///< the owner accepted the request; effect still unproven
  Refused = 3,       ///< the owner declined
  Failed = 4,        ///< the owner reported failure
  EffectObserved = 5,///< an observation consistent with the intended effect exists
  Verified = 6,      ///< the effect was verified against its effect class
  Refuted = 7,       ///< the claimed effect was not borne out by evidence
  Unresolved = 8,    ///< the process that owned this attempt died before its outcome
  Withdrawn = 9,     ///< the attempt was withdrawn before any effect
};

std::string_view to_token(AttemptState value) noexcept;
Result<AttemptState> attempt_state_from_token(std::string_view token);

/// True when an attempt has reached a state that cannot change on its own.
bool attempt_state_is_terminal(AttemptState value) noexcept;

/// True when the attempt was in flight when its owner stopped.
bool attempt_state_is_unresolved(AttemptState value) noexcept;

/// Result of one recovery-gate evaluation.
enum class RecoveryDecision : std::uint8_t {
  NotRequested = 0,
  Blocked = 1,   ///< at least one gate is unsatisfied
  Deferred = 2,  ///< every gate is satisfiable but a dwell or hysteresis window is running
  Permitted = 3, ///< every gate passed on current evidence
};

std::string_view to_token(RecoveryDecision value) noexcept;
Result<RecoveryDecision> recovery_decision_from_token(std::string_view token);

/// One recovery gate. A gate is a named proof obligation, not a threshold owned
/// by this component: the threshold comes from the scope's declared policy.
enum class RecoveryGate : std::uint8_t {
  FlowKnown = 0,                ///< flow evidence is present and usable
  PressureKnown = 1,            ///< pressure evidence is present and usable
  LeakClear = 2,                ///< leak evidence positively reports no leak
  ThermalCapacityRestored = 3,  ///< measured capacity covers declared demand
  ThermalMarginRestored = 4,    ///< margin is inside the declared envelope
  AirflowRestored = 5,          ///< airflow evidence is present and usable
  ContainmentRestored = 6,      ///< containment evidence is present and closed
  ConfirmedClassesCleared = 7,  ///< no class remains Confirmed
  EffectVerified = 8,           ///< the intended effect was verified
  EvidenceCurrent = 9,          ///< every required channel is Current
  DwellElapsed = 10,            ///< the required stable interval has elapsed
  HysteresisElapsed = 11,       ///< the required hysteresis interval has elapsed
};

std::string_view to_token(RecoveryGate value) noexcept;
Result<RecoveryGate> recovery_gate_from_token(std::string_view token);

const RecoveryGate* recovery_gate_order() noexcept;
std::size_t recovery_gate_count() noexcept;

/// Protective restrictions this component may impose on a scope while a failure
/// is unresolved. A restriction is a bound, not an action: it says what must not
/// happen, and it is released only through a recovery gate evaluation.
enum class RestrictionKind : std::uint8_t {
  LoadCeiling = 0,          ///< the scope's heat rejection demand must stay below a bound
  NoNewWork = 1,            ///< no additional workload may be placed
  NoCapacityCommitment = 2, ///< capacity must not be committed to new obligations
  IsolateCoolantPath = 3,   ///< the coolant path must stay isolated
  HoldContainment = 4,      ///< containment must stay closed
  ReservedStandby = 5,      ///< standby cooling plant must remain reserved
  ManualHold = 6,           ///< a human owner holds the scope
};

std::string_view to_token(RestrictionKind value) noexcept;
Result<RestrictionKind> restriction_kind_from_token(std::string_view token);

const RestrictionKind* restriction_kind_order() noexcept;
std::size_t restriction_kind_count() noexcept;

// ---------------------------------------------------------------------------
// Scope shape
// ---------------------------------------------------------------------------

/// The grain at which cooling failure state is tracked.
enum class ScopeKind : std::uint8_t {
  Site = 0,
  Plant = 1,
  Loop = 2,
  Cdu = 3,
  HeatExchanger = 4,
  Rack = 5,
  Row = 6,
  ThermalZone = 7,
  AirHandlerGroup = 8,
  ContainmentZone = 9,
  WorkloadScope = 10,
};

std::string_view to_token(ScopeKind value) noexcept;
Result<ScopeKind> scope_kind_from_token(std::string_view token);

/// How a dependency between two scopes behaves when the upstream scope fails.
enum class DependencyKind : std::uint8_t {
  SuppliesCoolant = 0,   ///< upstream supplies coolant to downstream
  SuppliesAirflow = 1,   ///< upstream supplies conditioned air
  SharesPlant = 2,       ///< both scopes draw on the same plant
  SharesReturn = 3,      ///< both scopes share a return path
  SharesPowerTrain = 4,  ///< both scopes share the cooling power train
  HousesHeatLoad = 5,    ///< upstream houses the downstream heat load
};

std::string_view to_token(DependencyKind value) noexcept;
Result<DependencyKind> dependency_kind_from_token(std::string_view token);

// ---------------------------------------------------------------------------
// Authority binding
// ---------------------------------------------------------------------------

/// Outcome of checking a set of external authority bindings against the
/// bindings a decision was published under.
enum class BindingStatus : std::uint8_t {
  Current = 0,       ///< every binding matches the generation the decision was made against
  Stale = 1,         ///< an owner's generation advanced past the bound generation
  Unbound = 2,       ///< a required binding was never supplied
  Mismatched = 3,    ///< a topological binding names something else than the decision does
};

std::string_view to_token(BindingStatus value) noexcept;
Result<BindingStatus> binding_status_from_token(std::string_view token);

bool binding_status_is_current(BindingStatus value) noexcept;

}  // namespace dccp::cooling_failure_manager

#endif  // DCCP_COOLING_FAILURE_MANAGER_ENUMS_HPP
