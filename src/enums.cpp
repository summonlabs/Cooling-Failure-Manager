// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/cooling_failure_manager/enums.hpp"

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <string>
#include <string_view>

#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/text.hpp"

namespace dccp::cooling_failure_manager {
namespace {

// ---------------------------------------------------------------------------
// Token tables
//
// Each table is the single source of truth for one enumeration's tokens and is
// written in enumerator order, so row index == enumerator value. The
// compile-time checks below prove, for every table, that it is in enum order,
// that it names every enumerator (the last enumerator plus one equals the table
// size), that no two rows share a token and that every token is non-empty
// lowercase kebab-case. Tokens are part of the durable format: an existing
// token is never renamed or repurposed.
// ---------------------------------------------------------------------------

template <class Enum>
struct TokenEntry {
  Enum value;
  std::string_view token;
};

/// Rendering of a value that is not an enumerator. It is deliberately not a
/// legal token of any enumeration in this header, so encoding a corrupt value
/// produces text the strict decoder rejects with UnknownEnumToken instead of
/// text that would silently decode as a real value.
constexpr std::string_view kInvalidToken = "invalid";

template <class Enum, std::size_t Size>
constexpr bool tokens_are_in_enum_order(const TokenEntry<Enum> (&table)[Size]) noexcept {
  for (std::size_t index = 0; index < Size; ++index) {
    if (static_cast<std::size_t>(table[index].value) != index) {
      return false;
    }
  }
  return true;
}

template <class Enum, std::size_t Size>
constexpr bool tokens_are_non_empty(const TokenEntry<Enum> (&table)[Size]) noexcept {
  for (const TokenEntry<Enum>& entry : table) {
    if (entry.token.empty()) {
      return false;
    }
  }
  return true;
}

template <class Enum, std::size_t Size>
constexpr bool tokens_are_unique(const TokenEntry<Enum> (&table)[Size]) noexcept {
  for (std::size_t lhs = 0; lhs < Size; ++lhs) {
    for (std::size_t rhs = lhs + 1; rhs < Size; ++rhs) {
      if (table[lhs].token == table[rhs].token) {
        return false;
      }
    }
  }
  return true;
}

/// A canonical token is 1..64 bytes of lowercase ASCII letters and digits,
/// grouped by single hyphens with no leading, trailing or doubled hyphen.
template <class Enum, std::size_t Size>
constexpr bool tokens_are_kebab_case(const TokenEntry<Enum> (&table)[Size]) noexcept {
  for (const TokenEntry<Enum>& entry : table) {
    const std::string_view token = entry.token;
    if (token.empty() || token.size() > limits::kMaxTokenBytes) {
      return false;
    }
    if (token.front() == '-' || token.back() == '-') {
      return false;
    }
    bool previous_hyphen = false;
    for (const char character : token) {
      const bool alphanumeric =
          (character >= '0' && character <= '9') || (character >= 'a' && character <= 'z');
      if (character == '-') {
        if (previous_hyphen) {
          return false;
        }
        previous_hyphen = true;
        continue;
      }
      if (!alphanumeric) {
        return false;
      }
      previous_hyphen = false;
    }
  }
  return true;
}

/// Proves that a token table names every enumerator: the enumerators are
/// contiguous from zero and the table is in enumerator order, so a table whose
/// size is one past the last enumerator covers the whole range exactly once.
template <class Enum, std::size_t Size>
constexpr bool tokens_cover_every_enumerator(const TokenEntry<Enum> (&table)[Size],
                                            std::size_t last_enumerator) noexcept {
  return tokens_are_in_enum_order(table) && Size == last_enumerator + 1u;
}

template <class Enum, std::size_t Size>
std::string_view token_of(Enum value, const TokenEntry<Enum> (&table)[Size]) noexcept {
  for (const TokenEntry<Enum>& entry : table) {
    if (entry.value == value) {
      return entry.token;
    }
  }
  return kInvalidToken;
}

/// Strict lookup. An unknown token is an error that names the token; it is
/// never mapped onto a default enumerator.
template <class Enum, std::size_t Size>
Result<Enum> from_token_impl(std::string_view token, std::string_view enum_name,
                             const TokenEntry<Enum> (&table)[Size]) {
  for (const TokenEntry<Enum>& entry : table) {
    if (entry.token == token) {
      return entry.value;
    }
  }
  // The token is untrusted, so the subject and the diagnostic are both bounded
  // to one token length before they become part of the error value.
  const std::string_view bounded = token.substr(0, limits::kMaxTokenBytes);
  return Error(ErrorCode::UnknownEnumToken,
               "unknown " + std::string(enum_name) + " token: " + escape_text(bounded))
      .with_subject(std::string(bounded));
}

// ---- Availability ---------------------------------------------------------

constexpr TokenEntry<Availability> kAvailabilityTokens[] = {
    {Availability::Indeterminate, "indeterminate"},
    {Availability::Observed, "observed"},
};

static_assert(tokens_cover_every_enumerator(kAvailabilityTokens,
                                            static_cast<std::size_t>(Availability::Observed)),
              "availability tokens must name every enumerator");
static_assert(tokens_are_unique(kAvailabilityTokens), "availability tokens must be unique");
static_assert(tokens_are_non_empty(kAvailabilityTokens), "availability tokens must be non-empty");
static_assert(tokens_are_kebab_case(kAvailabilityTokens), "availability tokens must be lowercase kebab-case");

// ---- ObservationQuality ---------------------------------------------------

constexpr TokenEntry<ObservationQuality> kObservationQualityTokens[] = {
    {ObservationQuality::Good, "good"},
    {ObservationQuality::Degraded, "degraded"},
    {ObservationQuality::Suspect, "suspect"},
    {ObservationQuality::Bad, "bad"},
};

static_assert(tokens_cover_every_enumerator(kObservationQualityTokens,
                                            static_cast<std::size_t>(ObservationQuality::Bad)),
              "observation quality tokens must name every enumerator");
static_assert(tokens_are_unique(kObservationQualityTokens), "observation quality tokens must be unique");
static_assert(tokens_are_non_empty(kObservationQualityTokens), "observation quality tokens must be non-empty");
static_assert(tokens_are_kebab_case(kObservationQualityTokens),
              "observation quality tokens must be lowercase kebab-case");

// ---- Freshness ------------------------------------------------------------

constexpr TokenEntry<Freshness> kFreshnessTokens[] = {
    {Freshness::Unobserved, "unobserved"},
    {Freshness::Stale, "stale"},
    {Freshness::Current, "current"},
    {Freshness::Future, "future"},
};

static_assert(tokens_cover_every_enumerator(kFreshnessTokens, static_cast<std::size_t>(Freshness::Future)),
              "freshness tokens must name every enumerator");
static_assert(tokens_are_unique(kFreshnessTokens), "freshness tokens must be unique");
static_assert(tokens_are_non_empty(kFreshnessTokens), "freshness tokens must be non-empty");
static_assert(tokens_are_kebab_case(kFreshnessTokens), "freshness tokens must be lowercase kebab-case");

// ---- ConfirmationState ----------------------------------------------------

constexpr TokenEntry<ConfirmationState> kConfirmationStateTokens[] = {
    {ConfirmationState::Unknown, "unknown"},
    {ConfirmationState::Healthy, "healthy"},
    {ConfirmationState::Suspected, "suspected"},
    {ConfirmationState::Confirmed, "confirmed"},
    {ConfirmationState::Contradicted, "contradicted"},
    {ConfirmationState::Unsupported, "unsupported"},
};

static_assert(tokens_cover_every_enumerator(kConfirmationStateTokens,
                                            static_cast<std::size_t>(ConfirmationState::Unsupported)),
              "confirmation state tokens must name every enumerator");
static_assert(tokens_are_unique(kConfirmationStateTokens), "confirmation state tokens must be unique");
static_assert(tokens_are_non_empty(kConfirmationStateTokens), "confirmation state tokens must be non-empty");
static_assert(tokens_are_kebab_case(kConfirmationStateTokens),
              "confirmation state tokens must be lowercase kebab-case");

// ---- FailureClass ---------------------------------------------------------

constexpr TokenEntry<FailureClass> kFailureClassTokens[] = {
    {FailureClass::PlantLoss, "plant-loss"},
    {FailureClass::PumpFailure, "pump-failure"},
    {FailureClass::LoopDegradation, "loop-degradation"},
    {FailureClass::LoopLoss, "loop-loss"},
    {FailureClass::ChillerFailure, "chiller-failure"},
    {FailureClass::CduFailure, "cdu-failure"},
    {FailureClass::ValveFlowFailure, "valve-flow-failure"},
    {FailureClass::PressureFailure, "pressure-failure"},
    {FailureClass::CrahCracFailure, "crah-crac-failure"},
    {FailureClass::AirflowLoss, "airflow-loss"},
    {FailureClass::ContainmentBreach, "containment-breach"},
    {FailureClass::Leak, "leak"},
    {FailureClass::ThermalCapacityLoss, "thermal-capacity-loss"},
    {FailureClass::SharedSourceFailure, "shared-source-failure"},
    {FailureClass::ThermalRunaway, "thermal-runaway"},
};

static_assert(tokens_cover_every_enumerator(kFailureClassTokens,
                                            static_cast<std::size_t>(FailureClass::ThermalRunaway)),
              "failure class tokens must name every enumerator");
static_assert(tokens_are_unique(kFailureClassTokens), "failure class tokens must be unique");
static_assert(tokens_are_non_empty(kFailureClassTokens), "failure class tokens must be non-empty");
static_assert(tokens_are_kebab_case(kFailureClassTokens), "failure class tokens must be lowercase kebab-case");

// ---- Severity -------------------------------------------------------------

constexpr TokenEntry<Severity> kSeverityTokens[] = {
    {Severity::None, "none"},
    {Severity::Degraded, "degraded"},
    {Severity::Impaired, "impaired"},
    {Severity::Critical, "critical"},
    {Severity::Total, "total"},
};

static_assert(tokens_cover_every_enumerator(kSeverityTokens, static_cast<std::size_t>(Severity::Total)),
              "severity tokens must name every enumerator");
static_assert(tokens_are_unique(kSeverityTokens), "severity tokens must be unique");
static_assert(tokens_are_non_empty(kSeverityTokens), "severity tokens must be non-empty");
static_assert(tokens_are_kebab_case(kSeverityTokens), "severity tokens must be lowercase kebab-case");

// ---- Urgency --------------------------------------------------------------

constexpr TokenEntry<Urgency> kUrgencyTokens[] = {
    {Urgency::Routine, "routine"},
    {Urgency::Elevated, "elevated"},
    {Urgency::Imminent, "imminent"},
    {Urgency::Immediate, "immediate"},
};

static_assert(tokens_cover_every_enumerator(kUrgencyTokens, static_cast<std::size_t>(Urgency::Immediate)),
              "urgency tokens must name every enumerator");
static_assert(tokens_are_unique(kUrgencyTokens), "urgency tokens must be unique");
static_assert(tokens_are_non_empty(kUrgencyTokens), "urgency tokens must be non-empty");
static_assert(tokens_are_kebab_case(kUrgencyTokens), "urgency tokens must be lowercase kebab-case");

// ---- TimeToImpact ---------------------------------------------------------

constexpr TokenEntry<TimeToImpact> kTimeToImpactTokens[] = {
    {TimeToImpact::Unobserved, "unobserved"},
    {TimeToImpact::Zero, "zero"},
    {TimeToImpact::Minutes, "minutes"},
    {TimeToImpact::TensOfMinutes, "tens-of-minutes"},
    {TimeToImpact::Hours, "hours"},
    {TimeToImpact::Days, "days"},
};

static_assert(tokens_cover_every_enumerator(kTimeToImpactTokens,
                                            static_cast<std::size_t>(TimeToImpact::Days)),
              "time to impact tokens must name every enumerator");
static_assert(tokens_are_unique(kTimeToImpactTokens), "time to impact tokens must be unique");
static_assert(tokens_are_non_empty(kTimeToImpactTokens), "time to impact tokens must be non-empty");
static_assert(tokens_are_kebab_case(kTimeToImpactTokens),
              "time to impact tokens must be lowercase kebab-case");

// ---- ObservationChannel ---------------------------------------------------

constexpr TokenEntry<ObservationChannel> kObservationChannelTokens[] = {
    {ObservationChannel::FlowMeter, "flow-meter"},
    {ObservationChannel::DifferentialPressure, "differential-pressure"},
    {ObservationChannel::AbsolutePressure, "absolute-pressure"},
    {ObservationChannel::CoolantTemperature, "coolant-temperature"},
    {ObservationChannel::AirTemperature, "air-temperature"},
    {ObservationChannel::LeakDetector, "leak-detector"},
    {ObservationChannel::PumpStatus, "pump-status"},
    {ObservationChannel::ValvePosition, "valve-position"},
    {ObservationChannel::ChillerStatus, "chiller-status"},
    {ObservationChannel::CduStatus, "cdu-status"},
    {ObservationChannel::CrahCracStatus, "crah-crac-status"},
    {ObservationChannel::AirflowMeter, "airflow-meter"},
    {ObservationChannel::ContainmentSwitch, "containment-switch"},
    {ObservationChannel::ThermalCapacityMeter, "thermal-capacity-meter"},
    {ObservationChannel::ThermalLoadMeter, "thermal-load-meter"},
    {ObservationChannel::ThermalMarginMeter, "thermal-margin-meter"},
    {ObservationChannel::HumiditySensor, "humidity-sensor"},
};

static_assert(tokens_cover_every_enumerator(kObservationChannelTokens,
                                            static_cast<std::size_t>(ObservationChannel::HumiditySensor)),
              "observation channel tokens must name every enumerator");
static_assert(tokens_are_unique(kObservationChannelTokens), "observation channel tokens must be unique");
static_assert(tokens_are_non_empty(kObservationChannelTokens), "observation channel tokens must be non-empty");
static_assert(tokens_are_kebab_case(kObservationChannelTokens),
              "observation channel tokens must be lowercase kebab-case");

// ---- LeakState ------------------------------------------------------------

constexpr TokenEntry<LeakState> kLeakStateTokens[] = {
    {LeakState::LeakUnknown, "leak-unknown"},
    {LeakState::LeakNone, "leak-none"},
    {LeakState::LeakSuspected, "leak-suspected"},
    {LeakState::LeakConfirmed, "leak-confirmed"},
    {LeakState::LeakActive, "leak-active"},
};

static_assert(tokens_cover_every_enumerator(kLeakStateTokens, static_cast<std::size_t>(LeakState::LeakActive)),
              "leak state tokens must name every enumerator");
static_assert(tokens_are_unique(kLeakStateTokens), "leak state tokens must be unique");
static_assert(tokens_are_non_empty(kLeakStateTokens), "leak state tokens must be non-empty");
static_assert(tokens_are_kebab_case(kLeakStateTokens), "leak state tokens must be lowercase kebab-case");

// ---- EvidenceStatus -------------------------------------------------------

constexpr TokenEntry<EvidenceStatus> kEvidenceStatusTokens[] = {
    {EvidenceStatus::Current, "current"},
    {EvidenceStatus::Missing, "missing"},
    {EvidenceStatus::Stale, "stale"},
    {EvidenceStatus::Conflicting, "conflicting"},
    {EvidenceStatus::OutOfOrder, "out-of-order"},
    {EvidenceStatus::Unbound, "unbound"},
    {EvidenceStatus::Indeterminate, "indeterminate"},
    {EvidenceStatus::Future, "future"},
};

static_assert(tokens_cover_every_enumerator(kEvidenceStatusTokens,
                                            static_cast<std::size_t>(EvidenceStatus::Future)),
              "evidence status tokens must name every enumerator");
static_assert(tokens_are_unique(kEvidenceStatusTokens), "evidence status tokens must be unique");
static_assert(tokens_are_non_empty(kEvidenceStatusTokens), "evidence status tokens must be non-empty");
static_assert(tokens_are_kebab_case(kEvidenceStatusTokens),
              "evidence status tokens must be lowercase kebab-case");

// ---- ResponseAction -------------------------------------------------------

constexpr TokenEntry<ResponseAction> kResponseActionTokens[] = {
    {ResponseAction::ObserveOnly, "observe-only"},
    {ResponseAction::VerifyEvidence, "verify-evidence"},
    {ResponseAction::IsolateScope, "isolate-scope"},
    {ResponseAction::FailoverCoolingSource, "failover-cooling-source"},
    {ResponseAction::StartStandbyPump, "start-standby-pump"},
    {ResponseAction::StartStandbyChiller, "start-standby-chiller"},
    {ResponseAction::OpenBypassValve, "open-bypass-valve"},
    {ResponseAction::CloseIsolationValve, "close-isolation-valve"},
    {ResponseAction::RaiseFanSpeed, "raise-fan-speed"},
    {ResponseAction::ReduceThermalLoad, "reduce-thermal-load"},
    {ResponseAction::ThrottleWorkload, "throttle-workload"},
    {ResponseAction::EvacuateScope, "evacuate-scope"},
    {ResponseAction::EmergencyShutdown, "emergency-shutdown"},
    {ResponseAction::ManualIntervention, "manual-intervention"},
};

static_assert(tokens_cover_every_enumerator(kResponseActionTokens,
                                            static_cast<std::size_t>(ResponseAction::ManualIntervention)),
              "response action tokens must name every enumerator");
static_assert(tokens_are_unique(kResponseActionTokens), "response action tokens must be unique");
static_assert(tokens_are_non_empty(kResponseActionTokens), "response action tokens must be non-empty");
static_assert(tokens_are_kebab_case(kResponseActionTokens),
              "response action tokens must be lowercase kebab-case");

// ---- EffectClass ----------------------------------------------------------

constexpr TokenEntry<EffectClass> kEffectClassTokens[] = {
    {EffectClass::None, "none"},
    {EffectClass::FlowRestored, "flow-restored"},
    {EffectClass::PressureRestored, "pressure-restored"},
    {EffectClass::TemperatureContained, "temperature-contained"},
    {EffectClass::ThermalCapacityRestored, "thermal-capacity-restored"},
    {EffectClass::LeakContained, "leak-contained"},
    {EffectClass::ContainmentRestored, "containment-restored"},
    {EffectClass::LoadReduced, "load-reduced"},
};

static_assert(tokens_cover_every_enumerator(kEffectClassTokens,
                                            static_cast<std::size_t>(EffectClass::LoadReduced)),
              "effect class tokens must name every enumerator");
static_assert(tokens_are_unique(kEffectClassTokens), "effect class tokens must be unique");
static_assert(tokens_are_non_empty(kEffectClassTokens), "effect class tokens must be non-empty");
static_assert(tokens_are_kebab_case(kEffectClassTokens), "effect class tokens must be lowercase kebab-case");

// ---- PlanLifecycle --------------------------------------------------------

constexpr TokenEntry<PlanLifecycle> kPlanLifecycleTokens[] = {
    {PlanLifecycle::Unplanned, "unplanned"},
    {PlanLifecycle::Planned, "planned"},
    {PlanLifecycle::Solicited, "solicited"},
    {PlanLifecycle::Active, "active"},
    {PlanLifecycle::Stabilized, "stabilized"},
    {PlanLifecycle::Recovering, "recovering"},
    {PlanLifecycle::Recovered, "recovered"},
    {PlanLifecycle::Withdrawn, "withdrawn"},
};

static_assert(tokens_cover_every_enumerator(kPlanLifecycleTokens,
                                            static_cast<std::size_t>(PlanLifecycle::Withdrawn)),
              "plan lifecycle tokens must name every enumerator");
static_assert(tokens_are_unique(kPlanLifecycleTokens), "plan lifecycle tokens must be unique");
static_assert(tokens_are_non_empty(kPlanLifecycleTokens), "plan lifecycle tokens must be non-empty");
static_assert(tokens_are_kebab_case(kPlanLifecycleTokens),
              "plan lifecycle tokens must be lowercase kebab-case");

// ---- AttemptState ---------------------------------------------------------

constexpr TokenEntry<AttemptState> kAttemptStateTokens[] = {
    {AttemptState::Planned, "planned"},
    {AttemptState::Solicited, "solicited"},
    {AttemptState::Acknowledged, "acknowledged"},
    {AttemptState::Refused, "refused"},
    {AttemptState::Failed, "failed"},
    {AttemptState::EffectObserved, "effect-observed"},
    {AttemptState::Verified, "verified"},
    {AttemptState::Refuted, "refuted"},
    {AttemptState::Unresolved, "unresolved"},
    {AttemptState::Withdrawn, "withdrawn"},
};

static_assert(tokens_cover_every_enumerator(kAttemptStateTokens,
                                            static_cast<std::size_t>(AttemptState::Withdrawn)),
              "attempt state tokens must name every enumerator");
static_assert(tokens_are_unique(kAttemptStateTokens), "attempt state tokens must be unique");
static_assert(tokens_are_non_empty(kAttemptStateTokens), "attempt state tokens must be non-empty");
static_assert(tokens_are_kebab_case(kAttemptStateTokens),
              "attempt state tokens must be lowercase kebab-case");

// ---- RecoveryDecision -----------------------------------------------------

constexpr TokenEntry<RecoveryDecision> kRecoveryDecisionTokens[] = {
    {RecoveryDecision::NotRequested, "not-requested"},
    {RecoveryDecision::Blocked, "blocked"},
    {RecoveryDecision::Deferred, "deferred"},
    {RecoveryDecision::Permitted, "permitted"},
};

static_assert(tokens_cover_every_enumerator(kRecoveryDecisionTokens,
                                            static_cast<std::size_t>(RecoveryDecision::Permitted)),
              "recovery decision tokens must name every enumerator");
static_assert(tokens_are_unique(kRecoveryDecisionTokens), "recovery decision tokens must be unique");
static_assert(tokens_are_non_empty(kRecoveryDecisionTokens), "recovery decision tokens must be non-empty");
static_assert(tokens_are_kebab_case(kRecoveryDecisionTokens),
              "recovery decision tokens must be lowercase kebab-case");

// ---- RecoveryGate ---------------------------------------------------------

constexpr TokenEntry<RecoveryGate> kRecoveryGateTokens[] = {
    {RecoveryGate::FlowKnown, "flow-known"},
    {RecoveryGate::PressureKnown, "pressure-known"},
    {RecoveryGate::LeakClear, "leak-clear"},
    {RecoveryGate::ThermalCapacityRestored, "thermal-capacity-restored"},
    {RecoveryGate::ThermalMarginRestored, "thermal-margin-restored"},
    {RecoveryGate::AirflowRestored, "airflow-restored"},
    {RecoveryGate::ContainmentRestored, "containment-restored"},
    {RecoveryGate::ConfirmedClassesCleared, "confirmed-classes-cleared"},
    {RecoveryGate::EffectVerified, "effect-verified"},
    {RecoveryGate::EvidenceCurrent, "evidence-current"},
    {RecoveryGate::DwellElapsed, "dwell-elapsed"},
    {RecoveryGate::HysteresisElapsed, "hysteresis-elapsed"},
};

static_assert(tokens_cover_every_enumerator(kRecoveryGateTokens,
                                            static_cast<std::size_t>(RecoveryGate::HysteresisElapsed)),
              "recovery gate tokens must name every enumerator");
static_assert(tokens_are_unique(kRecoveryGateTokens), "recovery gate tokens must be unique");
static_assert(tokens_are_non_empty(kRecoveryGateTokens), "recovery gate tokens must be non-empty");
static_assert(tokens_are_kebab_case(kRecoveryGateTokens), "recovery gate tokens must be lowercase kebab-case");

// ---- RestrictionKind ------------------------------------------------------

constexpr TokenEntry<RestrictionKind> kRestrictionKindTokens[] = {
    {RestrictionKind::LoadCeiling, "load-ceiling"},
    {RestrictionKind::NoNewWork, "no-new-work"},
    {RestrictionKind::NoCapacityCommitment, "no-capacity-commitment"},
    {RestrictionKind::IsolateCoolantPath, "isolate-coolant-path"},
    {RestrictionKind::HoldContainment, "hold-containment"},
    {RestrictionKind::ReservedStandby, "reserved-standby"},
    {RestrictionKind::ManualHold, "manual-hold"},
};

static_assert(tokens_cover_every_enumerator(kRestrictionKindTokens,
                                            static_cast<std::size_t>(RestrictionKind::ManualHold)),
              "restriction kind tokens must name every enumerator");
static_assert(tokens_are_unique(kRestrictionKindTokens), "restriction kind tokens must be unique");
static_assert(tokens_are_non_empty(kRestrictionKindTokens), "restriction kind tokens must be non-empty");
static_assert(tokens_are_kebab_case(kRestrictionKindTokens),
              "restriction kind tokens must be lowercase kebab-case");

// ---- ScopeKind ------------------------------------------------------------

constexpr TokenEntry<ScopeKind> kScopeKindTokens[] = {
    {ScopeKind::Site, "site"},
    {ScopeKind::Plant, "plant"},
    {ScopeKind::Loop, "loop"},
    {ScopeKind::Cdu, "cdu"},
    {ScopeKind::HeatExchanger, "heat-exchanger"},
    {ScopeKind::Rack, "rack"},
    {ScopeKind::Row, "row"},
    {ScopeKind::ThermalZone, "thermal-zone"},
    {ScopeKind::AirHandlerGroup, "air-handler-group"},
    {ScopeKind::ContainmentZone, "containment-zone"},
    {ScopeKind::WorkloadScope, "workload-scope"},
};

static_assert(tokens_cover_every_enumerator(kScopeKindTokens,
                                            static_cast<std::size_t>(ScopeKind::WorkloadScope)),
              "scope kind tokens must name every enumerator");
static_assert(tokens_are_unique(kScopeKindTokens), "scope kind tokens must be unique");
static_assert(tokens_are_non_empty(kScopeKindTokens), "scope kind tokens must be non-empty");
static_assert(tokens_are_kebab_case(kScopeKindTokens), "scope kind tokens must be lowercase kebab-case");

// ---- DependencyKind -------------------------------------------------------

constexpr TokenEntry<DependencyKind> kDependencyKindTokens[] = {
    {DependencyKind::SuppliesCoolant, "supplies-coolant"},
    {DependencyKind::SuppliesAirflow, "supplies-airflow"},
    {DependencyKind::SharesPlant, "shares-plant"},
    {DependencyKind::SharesReturn, "shares-return"},
    {DependencyKind::SharesPowerTrain, "shares-power-train"},
    {DependencyKind::HousesHeatLoad, "houses-heat-load"},
};

static_assert(tokens_cover_every_enumerator(kDependencyKindTokens,
                                            static_cast<std::size_t>(DependencyKind::HousesHeatLoad)),
              "dependency kind tokens must name every enumerator");
static_assert(tokens_are_unique(kDependencyKindTokens), "dependency kind tokens must be unique");
static_assert(tokens_are_non_empty(kDependencyKindTokens), "dependency kind tokens must be non-empty");
static_assert(tokens_are_kebab_case(kDependencyKindTokens),
              "dependency kind tokens must be lowercase kebab-case");

// ---- BindingStatus --------------------------------------------------------

constexpr TokenEntry<BindingStatus> kBindingStatusTokens[] = {
    {BindingStatus::Current, "current"},
    {BindingStatus::Stale, "stale"},
    {BindingStatus::Unbound, "unbound"},
    {BindingStatus::Mismatched, "mismatched"},
};

static_assert(tokens_cover_every_enumerator(kBindingStatusTokens,
                                            static_cast<std::size_t>(BindingStatus::Mismatched)),
              "binding status tokens must name every enumerator");
static_assert(tokens_are_unique(kBindingStatusTokens), "binding status tokens must be unique");
static_assert(tokens_are_non_empty(kBindingStatusTokens), "binding status tokens must be non-empty");
static_assert(tokens_are_kebab_case(kBindingStatusTokens),
              "binding status tokens must be lowercase kebab-case");

// ---------------------------------------------------------------------------
// Order tables
//
// A deterministic iteration over an enumeration is always in enumerator order,
// which is the canonical order. Each table is checked at compile time to be in
// enum order and to be one longer than the last enumerator, so it is complete.
// ---------------------------------------------------------------------------

template <class Enum, std::size_t Size>
constexpr bool is_enum_order(const Enum (&table)[Size]) noexcept {
  for (std::size_t index = 0; index < Size; ++index) {
    if (static_cast<std::size_t>(table[index]) != index) {
      return false;
    }
  }
  return true;
}

constexpr FailureClass kFailureClassOrder[] = {
    FailureClass::PlantLoss,        FailureClass::PumpFailure,          FailureClass::LoopDegradation,
    FailureClass::LoopLoss,         FailureClass::ChillerFailure,       FailureClass::CduFailure,
    FailureClass::ValveFlowFailure, FailureClass::PressureFailure,      FailureClass::CrahCracFailure,
    FailureClass::AirflowLoss,      FailureClass::ContainmentBreach,    FailureClass::Leak,
    FailureClass::ThermalCapacityLoss, FailureClass::SharedSourceFailure, FailureClass::ThermalRunaway};

static_assert(is_enum_order(kFailureClassOrder), "failure class order must be the enumerator order");
static_assert(std::size(kFailureClassOrder) == static_cast<std::size_t>(FailureClass::ThermalRunaway) + 1u,
              "failure class order must name every enumerator");

constexpr ObservationChannel kObservationChannelOrder[] = {
    ObservationChannel::FlowMeter,           ObservationChannel::DifferentialPressure,
    ObservationChannel::AbsolutePressure,    ObservationChannel::CoolantTemperature,
    ObservationChannel::AirTemperature,      ObservationChannel::LeakDetector,
    ObservationChannel::PumpStatus,          ObservationChannel::ValvePosition,
    ObservationChannel::ChillerStatus,       ObservationChannel::CduStatus,
    ObservationChannel::CrahCracStatus,      ObservationChannel::AirflowMeter,
    ObservationChannel::ContainmentSwitch,   ObservationChannel::ThermalCapacityMeter,
    ObservationChannel::ThermalLoadMeter,    ObservationChannel::ThermalMarginMeter,
    ObservationChannel::HumiditySensor};

static_assert(is_enum_order(kObservationChannelOrder),
              "observation channel order must be the enumerator order");
static_assert(std::size(kObservationChannelOrder) ==
                  static_cast<std::size_t>(ObservationChannel::HumiditySensor) + 1u,
              "observation channel order must name every enumerator");

constexpr ResponseAction kResponseActionOrder[] = {
    ResponseAction::ObserveOnly,          ResponseAction::VerifyEvidence,
    ResponseAction::IsolateScope,         ResponseAction::FailoverCoolingSource,
    ResponseAction::StartStandbyPump,     ResponseAction::StartStandbyChiller,
    ResponseAction::OpenBypassValve,      ResponseAction::CloseIsolationValve,
    ResponseAction::RaiseFanSpeed,        ResponseAction::ReduceThermalLoad,
    ResponseAction::ThrottleWorkload,     ResponseAction::EvacuateScope,
    ResponseAction::EmergencyShutdown,    ResponseAction::ManualIntervention};

static_assert(is_enum_order(kResponseActionOrder), "response action order must be the enumerator order");
static_assert(std::size(kResponseActionOrder) ==
                  static_cast<std::size_t>(ResponseAction::ManualIntervention) + 1u,
              "response action order must name every enumerator");

constexpr RecoveryGate kRecoveryGateOrder[] = {
    RecoveryGate::FlowKnown,               RecoveryGate::PressureKnown,
    RecoveryGate::LeakClear,               RecoveryGate::ThermalCapacityRestored,
    RecoveryGate::ThermalMarginRestored,   RecoveryGate::AirflowRestored,
    RecoveryGate::ContainmentRestored,     RecoveryGate::ConfirmedClassesCleared,
    RecoveryGate::EffectVerified,          RecoveryGate::EvidenceCurrent,
    RecoveryGate::DwellElapsed,            RecoveryGate::HysteresisElapsed};

static_assert(is_enum_order(kRecoveryGateOrder), "recovery gate order must be the enumerator order");
static_assert(std::size(kRecoveryGateOrder) ==
                  static_cast<std::size_t>(RecoveryGate::HysteresisElapsed) + 1u,
              "recovery gate order must name every enumerator");

constexpr RestrictionKind kRestrictionKindOrder[] = {
    RestrictionKind::LoadCeiling,        RestrictionKind::NoNewWork,
    RestrictionKind::NoCapacityCommitment, RestrictionKind::IsolateCoolantPath,
    RestrictionKind::HoldContainment,    RestrictionKind::ReservedStandby,
    RestrictionKind::ManualHold};

static_assert(is_enum_order(kRestrictionKindOrder), "restriction kind order must be the enumerator order");
static_assert(std::size(kRestrictionKindOrder) ==
                  static_cast<std::size_t>(RestrictionKind::ManualHold) + 1u,
              "restriction kind order must name every enumerator");

}  // namespace

// ---------------------------------------------------------------------------
// Token rendering and strict parsing
// ---------------------------------------------------------------------------

std::string_view to_token(Availability value) noexcept { return token_of(value, kAvailabilityTokens); }
Result<Availability> availability_from_token(std::string_view token) {
  return from_token_impl(token, "availability", kAvailabilityTokens);
}

std::string_view to_token(ObservationQuality value) noexcept {
  return token_of(value, kObservationQualityTokens);
}
Result<ObservationQuality> observation_quality_from_token(std::string_view token) {
  return from_token_impl(token, "observation-quality", kObservationQualityTokens);
}

std::string_view to_token(Freshness value) noexcept { return token_of(value, kFreshnessTokens); }
Result<Freshness> freshness_from_token(std::string_view token) {
  return from_token_impl(token, "freshness", kFreshnessTokens);
}

std::string_view to_token(ConfirmationState value) noexcept {
  return token_of(value, kConfirmationStateTokens);
}
Result<ConfirmationState> confirmation_state_from_token(std::string_view token) {
  return from_token_impl(token, "confirmation-state", kConfirmationStateTokens);
}

std::string_view to_token(FailureClass value) noexcept { return token_of(value, kFailureClassTokens); }
Result<FailureClass> failure_class_from_token(std::string_view token) {
  return from_token_impl(token, "failure-class", kFailureClassTokens);
}

std::string_view to_token(Severity value) noexcept { return token_of(value, kSeverityTokens); }
Result<Severity> severity_from_token(std::string_view token) {
  return from_token_impl(token, "severity", kSeverityTokens);
}

std::string_view to_token(Urgency value) noexcept { return token_of(value, kUrgencyTokens); }
Result<Urgency> urgency_from_token(std::string_view token) {
  return from_token_impl(token, "urgency", kUrgencyTokens);
}

std::string_view to_token(TimeToImpact value) noexcept { return token_of(value, kTimeToImpactTokens); }
Result<TimeToImpact> time_to_impact_from_token(std::string_view token) {
  return from_token_impl(token, "time-to-impact", kTimeToImpactTokens);
}

std::string_view to_token(ObservationChannel value) noexcept {
  return token_of(value, kObservationChannelTokens);
}
Result<ObservationChannel> observation_channel_from_token(std::string_view token) {
  return from_token_impl(token, "observation-channel", kObservationChannelTokens);
}

std::string_view to_token(LeakState value) noexcept { return token_of(value, kLeakStateTokens); }
Result<LeakState> leak_state_from_token(std::string_view token) {
  return from_token_impl(token, "leak-state", kLeakStateTokens);
}

std::string_view to_token(EvidenceStatus value) noexcept { return token_of(value, kEvidenceStatusTokens); }
Result<EvidenceStatus> evidence_status_from_token(std::string_view token) {
  return from_token_impl(token, "evidence-status", kEvidenceStatusTokens);
}

std::string_view to_token(ResponseAction value) noexcept { return token_of(value, kResponseActionTokens); }
Result<ResponseAction> response_action_from_token(std::string_view token) {
  return from_token_impl(token, "response-action", kResponseActionTokens);
}

std::string_view to_token(EffectClass value) noexcept { return token_of(value, kEffectClassTokens); }
Result<EffectClass> effect_class_from_token(std::string_view token) {
  return from_token_impl(token, "effect-class", kEffectClassTokens);
}

std::string_view to_token(PlanLifecycle value) noexcept { return token_of(value, kPlanLifecycleTokens); }
Result<PlanLifecycle> plan_lifecycle_from_token(std::string_view token) {
  return from_token_impl(token, "plan-lifecycle", kPlanLifecycleTokens);
}

std::string_view to_token(AttemptState value) noexcept { return token_of(value, kAttemptStateTokens); }
Result<AttemptState> attempt_state_from_token(std::string_view token) {
  return from_token_impl(token, "attempt-state", kAttemptStateTokens);
}

std::string_view to_token(RecoveryDecision value) noexcept {
  return token_of(value, kRecoveryDecisionTokens);
}
Result<RecoveryDecision> recovery_decision_from_token(std::string_view token) {
  return from_token_impl(token, "recovery-decision", kRecoveryDecisionTokens);
}

std::string_view to_token(RecoveryGate value) noexcept { return token_of(value, kRecoveryGateTokens); }
Result<RecoveryGate> recovery_gate_from_token(std::string_view token) {
  return from_token_impl(token, "recovery-gate", kRecoveryGateTokens);
}

std::string_view to_token(RestrictionKind value) noexcept { return token_of(value, kRestrictionKindTokens); }
Result<RestrictionKind> restriction_kind_from_token(std::string_view token) {
  return from_token_impl(token, "restriction-kind", kRestrictionKindTokens);
}

std::string_view to_token(ScopeKind value) noexcept { return token_of(value, kScopeKindTokens); }
Result<ScopeKind> scope_kind_from_token(std::string_view token) {
  return from_token_impl(token, "scope-kind", kScopeKindTokens);
}

std::string_view to_token(DependencyKind value) noexcept { return token_of(value, kDependencyKindTokens); }
Result<DependencyKind> dependency_kind_from_token(std::string_view token) {
  return from_token_impl(token, "dependency-kind", kDependencyKindTokens);
}

std::string_view to_token(BindingStatus value) noexcept { return token_of(value, kBindingStatusTokens); }
Result<BindingStatus> binding_status_from_token(std::string_view token) {
  return from_token_impl(token, "binding-status", kBindingStatusTokens);
}

// ---------------------------------------------------------------------------
// Order tables
// ---------------------------------------------------------------------------

const FailureClass* failure_class_order() noexcept { return kFailureClassOrder; }
std::size_t failure_class_count() noexcept { return std::size(kFailureClassOrder); }

const ObservationChannel* observation_channel_order() noexcept { return kObservationChannelOrder; }
std::size_t observation_channel_count() noexcept { return std::size(kObservationChannelOrder); }

const ResponseAction* response_action_order() noexcept { return kResponseActionOrder; }
std::size_t response_action_count() noexcept { return std::size(kResponseActionOrder); }

const RecoveryGate* recovery_gate_order() noexcept { return kRecoveryGateOrder; }
std::size_t recovery_gate_count() noexcept { return std::size(kRecoveryGateOrder); }

const RestrictionKind* restriction_kind_order() noexcept { return kRestrictionKindOrder; }
std::size_t restriction_kind_count() noexcept { return std::size(kRestrictionKindOrder); }

// ---------------------------------------------------------------------------
// Policy predicates
//
// These are named rules, not thresholds: every caller and every test must reach
// the same answer for the same enumerator, so each one lists its whole truth set
// explicitly and an enumerator added later cannot silently join a truth set.
// ---------------------------------------------------------------------------

bool failure_class_is_total_loss(FailureClass value) noexcept {
  // True only for a class that is a loss of the whole cooling function of a scope
  // rather than a degradation of it. This predicate is what makes an upstream
  // failure attributable: only a scope that has lost its cooling function
  // entirely imposes a shared-source loss on everything that depends on it.
  //
  // The two negative cases that are easy to get wrong are stated explicitly:
  //   * ChillerFailure names ONE chiller unit failed inside a live plant, so the
  //     plant still rejects heat at reduced capacity and the scope has not lost
  //     its function;
  //   * CrahCracFailure names ONE air-handling unit failed, and AirflowLoss is
  //     the class for the loss of airflow itself.
  // A degradation is not a loss: attributing either of them downstream would tell
  // every dependent scope that it had lost its cooling when it had not.
  switch (value) {
    case FailureClass::PlantLoss:
    case FailureClass::LoopLoss:
    case FailureClass::CduFailure:
    case FailureClass::SharedSourceFailure:
    case FailureClass::ThermalRunaway:
      return true;
    case FailureClass::PumpFailure:
    case FailureClass::ChillerFailure:
    case FailureClass::LoopDegradation:
    case FailureClass::ValveFlowFailure:
    case FailureClass::PressureFailure:
    case FailureClass::CrahCracFailure:
    case FailureClass::AirflowLoss:
    case FailureClass::ContainmentBreach:
    case FailureClass::Leak:
    case FailureClass::ThermalCapacityLoss:
      return false;
  }
  return false;
}

bool severity_at_least(Severity value, Severity floor) noexcept {
  // The enumeration is declared in increasing impact, and that order is fixed.
  return static_cast<std::uint8_t>(value) >= static_cast<std::uint8_t>(floor);
}

bool urgency_at_least(Urgency value, Urgency floor) noexcept {
  // The enumeration is declared in increasing urgency, and that order is fixed.
  return static_cast<std::uint8_t>(value) >= static_cast<std::uint8_t>(floor);
}

bool leak_state_is_clear(LeakState value) noexcept {
  // Only a positive "no leak" observation clears a leak gate. LeakUnknown is
  // the absence of an observation, which is not clearance.
  return value == LeakState::LeakNone;
}

bool evidence_status_is_usable(EvidenceStatus value) noexcept {
  // Every other status names a reason the observation may not be used, so only
  // Current can satisfy a confirmation or a recovery gate.
  return value == EvidenceStatus::Current;
}

bool response_action_is_load_reduction(ResponseAction value) noexcept {
  // Actions whose only cooling effect is to reduce the heat the scope must
  // reject; they cannot restore cooling function.
  switch (value) {
    case ResponseAction::ReduceThermalLoad:
    case ResponseAction::ThrottleWorkload:
    case ResponseAction::EvacuateScope:
    case ResponseAction::EmergencyShutdown:
      return true;
    default:
      return false;
  }
}

bool response_action_is_protective(ResponseAction value) noexcept {
  // Actions that bound harm to the scope or its neighbours rather than attempt
  // a recovery. RestrictionKind::HoldContainment is a restriction, not a
  // response action, so it is not named here.
  switch (value) {
    case ResponseAction::IsolateScope:
    case ResponseAction::CloseIsolationValve:
    case ResponseAction::EvacuateScope:
    case ResponseAction::EmergencyShutdown:
    case ResponseAction::ManualIntervention:
    case ResponseAction::ReduceThermalLoad:
    case ResponseAction::ThrottleWorkload:
      return true;
    default:
      return false;
  }
}

bool attempt_state_is_terminal(AttemptState value) noexcept {
  // A terminal attempt can never change on its own. Unresolved is deliberately
  // not terminal: it is precisely the state that still needs an explicit
  // decision. EffectObserved is not terminal either, because the effect still
  // has to be verified or refuted.
  switch (value) {
    case AttemptState::Refused:
    case AttemptState::Failed:
    case AttemptState::Verified:
    case AttemptState::Refuted:
    case AttemptState::Withdrawn:
      return true;
    default:
      return false;
  }
}

bool attempt_state_is_unresolved(AttemptState value) noexcept {
  return value == AttemptState::Unresolved;
}

bool binding_status_is_current(BindingStatus value) noexcept {
  return value == BindingStatus::Current;
}

}  // namespace dccp::cooling_failure_manager
