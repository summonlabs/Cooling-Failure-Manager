// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_COOLING_FAILURE_MANAGER_EVIDENCE_HPP
#define DCCP_COOLING_FAILURE_MANAGER_EVIDENCE_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "dccp/cooling_failure_manager/enums.hpp"
#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/model.hpp"
#include "dccp/cooling_failure_manager/result.hpp"
#include "dccp/cooling_failure_manager/strong_id.hpp"

namespace dccp::cooling_failure_manager {

// ===========================================================================
// Observations
// ===========================================================================

/// A scalar reading on one observation channel.
///
/// The type makes the central rule structural rather than documented: a reading
/// is either Observed - it has a value, a quality and a producing sequence - or
/// it is Indeterminate, in which case it has no value at all. There is no
/// zero-valued "unknown", so a missing flow reading can never be summed,
/// averaged, compared or reported as a healthy zero. observed_value() refuses an
/// indeterminate quantity instead of returning 0.
///
/// The unit string is the channel's unit as declared by the producer
/// ("mL/s", "Pa", "mC", ...). This component never converts between units: it
/// compares readings only against declared quantities carrying the same unit,
/// and reports a unit disagreement rather than guessing an exchange rate.
class Quantity {
 public:
  Quantity() noexcept = default;

  /// A reading that exists.
  static Result<Quantity> observed(std::int64_t value, std::string_view unit,
                                   ObservationQuality quality,
                                   ObservationSequence sequence);

  /// A reading that does not exist. Indeterminate quantities compare equal to
  /// each other and carry no value, quality or sequence.
  static Quantity indeterminate() noexcept { return Quantity(); }

  Availability availability() const noexcept { return availability_; }

  /// Only the producer's own quality claim; never promoted by this component.
  ObservationQuality quality() const noexcept { return quality_; }

  /// Sequence of the producing stream. Absent for an indeterminate quantity.
  ObservationSequence sequence() const noexcept { return sequence_; }

  bool has_value() const noexcept { return availability_ == Availability::Observed; }

  /// The reading. Refuses an indeterminate quantity with EvidenceMissing rather
  /// than substituting zero.
  Result<std::int64_t> observed_value() const;

  /// The reading, or nothing when the quantity is indeterminate.
  std::optional<std::int64_t> value_if_observed() const noexcept;

  const std::string& unit() const noexcept { return unit_; }

  /// True when this reading may be used as evidence: Observed and its quality is
  /// Good or Degraded. A Suspect or Bad reading is still recorded and still
  /// participates in conflict detection, but it cannot confirm a failure and
  /// cannot satisfy a recovery gate.
  bool is_usable() const noexcept;

  friend bool operator==(const Quantity&, const Quantity&) noexcept = default;

 private:
  Availability availability_ = Availability::Indeterminate;
  ObservationQuality quality_ = ObservationQuality::Bad;
  ObservationSequence sequence_{};
  std::int64_t value_ = 0;
  std::string unit_;
};

/// One recorded observation of one channel on one scope.
///
/// An observation is immutable evidence: it records what a producer said and
/// when, on the caller-owned synthetic timeline. Nothing in the library ever
/// rewrites a recorded observation.
struct Observation {
  ObservationId id;
  ScopeId scope;
  ObservationChannel channel = ObservationChannel::FlowMeter;

  /// Observed scalar. Indeterminate is a first-class, recorded state: a channel
  /// may be instrumented and silent, which is different from absent, and both
  /// are different from healthy.
  Quantity quantity;

  /// Leak state. LeakUnknown is the default and never satisfies a gate.
  LeakState leak = LeakState::LeakUnknown;

  /// Clock at which the producer sampled the channel.
  DecisionClock observed_at{};
  /// Clock at which this component recorded the observation.
  DecisionClock recorded_at{};

  /// Which observation stream produced it.
  std::string producer;
  /// Producer's sensor identity, preserved verbatim.
  std::string sensor;
  /// Generation of the producer's observation stream.
  EvidenceGeneration evidence_generation{};
  /// True when the producer declared that the value is a carried-forward sample
  /// rather than a fresh one. A carried value keeps its own timestamp; it never
  /// ages forward.
  bool carried_forward = false;
};

/// True when the observation carries a reading on its channel at all. A
/// status-only channel (pump status, valve position, containment switch) may
/// legitimately carry a reading of zero.
bool observation_has_signal(const Observation& observation) noexcept;

/// True when the observation asserts a leak state other than LeakUnknown.
bool observation_asserts_leak(const Observation& observation) noexcept;

// ===========================================================================
// Observation set
// ===========================================================================

/// Bounds applied to one observation set before it is used.
struct ObservationLimits {
  std::size_t max_observations = limits::kMaxObservationCount;
  std::size_t max_observations_per_scope = limits::kMaxObservationPerScope;
};

/// The evidence a decision is computed from: every recorded observation, plus
/// the checks that make a subset usable.
///
/// The set is a value type. Duplicate observation identities, observations whose
/// scope is unknown, and observations that exceed a bound are refused when the
/// set is built, so the decision engine never has to handle a malformed set.
class ObservationSet {
 public:
  ObservationSet() = default;

  /// Adds one observation. Refuses a duplicate identity, an empty identity or a
  /// bound violation.
  Result<void> add(const Observation& observation);

  /// Adds many observations, rejecting the whole batch on the first refusal so
  /// a caller cannot end up with a half-applied update.
  Result<void> add_all(const std::vector<Observation>& observations);

  const std::vector<Observation>& observations() const noexcept { return observations_; }
  std::size_t size() const noexcept { return observations_.size(); }
  bool empty() const noexcept { return observations_.empty(); }

  /// Every observation for one scope, in canonical order.
  std::vector<const Observation*> for_scope(const ScopeId& scope) const;

  /// Every observation for one scope and channel, in canonical order (highest
  /// sequence first, then observation identity).
  std::vector<const Observation*> for_channel(const ScopeId& scope, ObservationChannel channel) const;

  /// The most recent usable-and-current observation on a channel at the decision
  /// clock, or nullptr. "Most recent" is the highest observation sequence, with
  /// ties broken by the later sampling clock and then by observation identity -
  /// never by insertion order.
  const Observation* latest(const ScopeId& scope, ObservationChannel channel,
                            const DecisionClock& clock, DurationMilliseconds window) const;

  /// Every observation on a channel that is dated at or after the given clock.
  std::vector<const Observation*> since(const ScopeId& scope, ObservationChannel channel,
                                        const DecisionClock& since) const;

  /// True when two recorded observations for the same scope and channel carry
  /// the same producer sequence but different readings: two streams, one
  /// sequence, two answers. Such a subject is Conflicting and unusable.
  bool has_conflict(const ScopeId& scope, ObservationChannel channel) const;

  /// Sorts into canonical order: (scope, channel, sequence, observation id).
  void sort_canonical();

 private:
  std::vector<Observation> observations_;
};

/// The decision-time status of one observation.
///
/// Freshness, availability and usability are three independent facts. This
/// struct keeps them independent so an explanation can say precisely what is
/// wrong instead of reporting a single opaque "bad" status.
struct ObservationUsability {
  EvidenceStatus status = EvidenceStatus::Missing;
  Freshness freshness = Freshness::Unobserved;
  std::int64_t age_milliseconds = 0;
  std::string detail;
};

/// Classifies one recorded observation against the decision clock and window.
/// A null observation means "nothing was recorded for this subject".
ObservationUsability assess_observation(const Observation* observation, const DecisionClock& clock,
                                        DurationMilliseconds window, bool conflicting);

// ===========================================================================
// Decision policy
// ===========================================================================

/// The evidence rules a decision is computed under.
///
/// The policy is an explicit input so that a decision can be reproduced exactly
/// and so that a change of policy is visible as a change of inputs rather than
/// as a silent change of behaviour.
struct DecisionPolicy {
  /// Default age beyond which an observation stops being current.
  DurationMilliseconds evidence_window{};
  /// Number of independent usable observations required to confirm a failure
  /// class. At least 1; a policy demanding 0 is refused.
  std::uint32_t confirm_min_observations = 1;
  /// Number of independent usable observations required to raise a suspicion.
  std::uint32_t suspect_min_observations = 1;
  /// Number of agreeing producer streams required to treat a class as healthy
  /// when the class's own channel is instrumented. A policy value above the
  /// number of available producers keeps the class Unknown rather than Healthy,
  /// which is the safe direction.
  std::uint32_t healthy_min_observations = 1;
  /// When true, a class may only be confirmed from a positive observation on the
  /// class's own witness channels; supporting channels can raise a suspicion but
  /// never confirm.
  bool require_direct_witness = true;
  /// Severity at or above which a confirmed failure is treated as a safety
  /// escalation that may be responded to immediately, without waiting for the
  /// dwell windows a recovery waits for.
  Severity safety_escalation_severity = Severity::Critical;
  /// Clock after which a solicited attempt with no recorded answer is reported
  /// as outstanding rather than in flight. Zero disables the report.
  DurationMilliseconds acknowledgement_window{};
};

/// Rejects a policy that cannot be evaluated (zero confirmation demand, a
/// window outside the accepted range).
Result<void> validate_policy(const DecisionPolicy& policy);

/// Builds an observation from untrusted parts, applying every bound.
Result<Observation> make_observation(const ObservationId& id, const ScopeId& scope,
                                     ObservationChannel channel, Quantity quantity,
                                     LeakState leak, const DecisionClock& observed_at,
                                     const DecisionClock& recorded_at, std::string_view producer,
                                     std::string_view sensor,
                                     EvidenceGeneration evidence_generation,
                                     bool carried_forward);

}  // namespace dccp::cooling_failure_manager

#endif  // DCCP_COOLING_FAILURE_MANAGER_EVIDENCE_HPP
