// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_COOLING_FAILURE_MANAGER_RECOVERY_HPP
#define DCCP_COOLING_FAILURE_MANAGER_RECOVERY_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "dccp/cooling_failure_manager/decision.hpp"
#include "dccp/cooling_failure_manager/enums.hpp"
#include "dccp/cooling_failure_manager/evidence.hpp"
#include "dccp/cooling_failure_manager/model.hpp"
#include "dccp/cooling_failure_manager/result.hpp"

namespace dccp::cooling_failure_manager {

/// The evidence a recovery must present, computed for one scope.
///
/// The demand is derived from the scope's declared policy and from the failure
/// classes that were confirmed. A caller may add requirements; a caller may not
/// remove them, because a recovery that presents less evidence than the failure
/// that caused it is not a recovery.
struct RecoveryRequirements {
  ScopeId scope;
  std::vector<ObservationChannel> required_observations;
  std::vector<FailureClass> required_cleared_classes;
  bool require_leak_clear = true;
  bool require_verified_effect = true;
  DurationMilliseconds dwell{};
  DurationMilliseconds hysteresis{};
  /// Clock at which the scope's stable interval started, supplied by the caller
  /// from its own decision history. A clock that is not present means the
  /// interval has not started, so the dwell gate is unsatisfied and the
  /// assessment is Deferred rather than Permitted.
  DecisionClock stable_since{};

  /// The state the scope's response plan lives in, so the effect gate can read
  /// the attempt that must have reached Verified. A demand with no snapshot
  /// cannot satisfy the effect gate, and says so rather than assuming an effect.
  ///
  /// The referenced state must outlive the evaluate_recovery() call. The engine
  /// never stores the pointer.
  const CoolingFailureState* state_snapshot = nullptr;
};

/// Computes the recovery requirements for one scope from its policy and the
/// classes confirmed against it. Classes that are Confirmed at the time of the
/// call are added to required_cleared_classes, so a recovery cannot be evaluated
/// against a demand that omits the failure it is recovering from.
Result<RecoveryRequirements> recovery_requirements(const CoolingScope& scope,
                                                   const ScopeDecision& decision);

/// Extends a recovery demand with the witness channels of every class it must
/// prove clear.
///
/// A caller that adds a clearance (because its own classification names more
/// classes than the engine's demand did) must call this afterwards: a demand that
/// names a class without demanding the channels that witness it would block the
/// recovery for want of evidence that was never requested.
Result<RecoveryRequirements> recovery_requirements_with_classes(
    const CoolingScope& scope, const ScopeDecision& decision, RecoveryRequirements requirements);

/// Evaluates every recovery gate for one scope.
///
/// The three possible outcomes are deliberately not collapsed:
///   * Permitted  - every gate passed on current evidence at the decision clock;
///   * Deferred   - every gate that can be checked now passed, but a dwell or
///                  hysteresis interval is still running; the assessment reports
///                  how long is left;
///   * Blocked    - at least one gate failed, and the assessment names it.
///
/// A recovery is never inferred from temperature alone. Thermal recovery needs
/// thermal capacity or margin evidence inside the declared envelope, and every
/// class that was confirmed must be positively cleared by usable evidence on its
/// own witness channel.
Result<RecoveryAssessment> evaluate_recovery(const CoolingScope& scope, const ScopeDecision& decision,
                                             const RecoveryRequirements& requirements,
                                             const ObservationSet& observations,
                                             const DecisionPolicy& policy, const DecisionClock& clock);

/// Stable, machine-readable explanation lines for one recovery assessment, in
/// canonical order.
std::vector<std::string> explain_recovery(const RecoveryAssessment& assessment);

/// True when a scope may leave its protective restrictions at this assessment.
bool recovery_releases_restrictions(const RecoveryAssessment& assessment) noexcept;

/// True when a scope in this assessment state must keep a human in the loop.
bool recovery_requires_manual_hold(const RecoveryAssessment& assessment) noexcept;

}  // namespace dccp::cooling_failure_manager

#endif  // DCCP_COOLING_FAILURE_MANAGER_RECOVERY_HPP
