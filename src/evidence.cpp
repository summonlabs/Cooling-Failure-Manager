// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/cooling_failure_manager/evidence.hpp"

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "dccp/cooling_failure_manager/classify.hpp"
#include "dccp/cooling_failure_manager/text.hpp"

namespace dccp::cooling_failure_manager {
namespace {

// ---------------------------------------------------------------------------
// Channel families
// ---------------------------------------------------------------------------
//
// The canonical unit is the single source of truth for what a channel carries:
// a channel with a unit carries a scalar measurement, a leak channel carries a
// leak assertion, and every other channel carries a discrete state code. Using
// the unit table instead of a second channel list keeps the two from drifting.

/// True when the channel carries a discrete state code (0 = normal, 1 =
/// degraded, 2 = failed) rather than a measurement.
bool is_status_only_channel(ObservationChannel channel) noexcept {
  return !channel_is_leak(channel) && channel_unit(channel).empty();
}

/// True when the channel carries a scalar measurement with a canonical unit.
bool is_scalar_channel(ObservationChannel channel) noexcept {
  return !channel_unit(channel).empty();
}

/// True when the observation asserts something about its channel: a reading, or
/// for a leak channel a leak state other than LeakUnknown. An observation that
/// asserts nothing is recorded evidence of a silent instrument, which is never
/// Current evidence for the channel.
bool observation_asserts_something(const Observation& observation) noexcept {
  if (observation.quantity.has_value()) {
    return true;
  }
  return channel_is_leak(observation.channel) && observation_asserts_leak(observation);
}

/// The last state code this taxonomy declares on a status channel: 0 is normal
/// (or closed as commanded), 1 is degraded (or partially open) and 2 is failed
/// (or open). A unit-less reading is such a code, so the domain is the whole
/// vocabulary it may carry.
inline constexpr std::int64_t kMaxStateCode = 2;

/// Explains why an external identity was refused, with the code that names the
/// exact reason: an absent field is MissingField, an over-long field is
/// TextTooLong, and bytes that are not valid UTF-8 are InvalidUtf8. The mapping
/// is deliberately identical to the one model.cpp applies to a binding owner and
/// identity, so a producer sees the same code from every entry point that
/// validates an external identity. The final branch is unreachable while
/// is_valid_external_identity() tests exactly those three conditions.
Result<void> require_external_identity(std::string_view value, std::size_t max_bytes,
                                       std::string_view what) {
  if (is_valid_external_identity(value, max_bytes)) {
    return ok();
  }
  if (value.empty()) {
    return Error(ErrorCode::MissingField, std::string(what) + " must not be empty");
  }
  if (value.size() > max_bytes) {
    return Error(ErrorCode::TextTooLong,
                 std::string(what) + " exceeds the bound of " + std::to_string(max_bytes) + " bytes")
        .with_subject(std::string(value.substr(0, 64)));
  }
  if (!is_valid_utf8(value)) {
    return Error(ErrorCode::InvalidUtf8, std::string(what) + " is not valid UTF-8")
        .with_subject(std::string(value.substr(0, 64)));
  }
  return Error(ErrorCode::MalformedIdentifier, std::string(what) + " is malformed")
      .with_subject(std::string(value.substr(0, 64)));
}

/// lhs - rhs computed without wrapping. Returns nothing when the difference is
/// not representable, which can only happen for a clock outside the range the
/// library accepts from a caller (DecisionClock::parse bounds every clock the
/// library stores).
std::optional<std::int64_t> checked_difference(std::int64_t lhs, std::int64_t rhs) noexcept {
  if (rhs > 0 && lhs < INT64_MIN + rhs) {
    return std::nullopt;
  }
  if (rhs < 0 && lhs > INT64_MAX + rhs) {
    return std::nullopt;
  }
  return lhs - rhs;
}

/// Canonical observation order: scope bytes, then channel index, then producer
/// sequence, then observation identity bytes. Every ordering in this file is
/// derived from it, so no result ever depends on insertion order.
bool canonical_order_less(const Observation& lhs, const Observation& rhs) noexcept {
  if (lhs.scope != rhs.scope) {
    return lhs.scope < rhs.scope;
  }
  const std::size_t lhs_channel = channel_index(lhs.channel);
  const std::size_t rhs_channel = channel_index(rhs.channel);
  if (lhs_channel != rhs_channel) {
    return lhs_channel < rhs_channel;
  }
  if (lhs.quantity.sequence() != rhs.quantity.sequence()) {
    return lhs.quantity.sequence() < rhs.quantity.sequence();
  }
  return lhs.id < rhs.id;
}

/// Two readings disagree when their availability differs, when two present
/// readings differ in value, or when their leak states differ. The quality is
/// deliberately not part of the comparison: a producer reporting the same value
/// with a worse quality is not contradicting its own reading, it is flagging its
/// confidence. The unit is not part of it either, because make_observation()
/// pins a scalar channel to exactly one canonical unit.
bool readings_differ(const Observation& lhs, const Observation& rhs) noexcept {
  if (lhs.quantity.availability() != rhs.quantity.availability()) {
    return true;
  }
  if (lhs.quantity.availability() == Availability::Observed &&
      lhs.quantity.value_if_observed() != rhs.quantity.value_if_observed()) {
    return true;
  }
  return lhs.leak != rhs.leak;
}

/// The most recent observation of a subject: highest producer sequence, ties
/// broken by the later sampling clock and then by the greater observation
/// identity. A total order, because observation identities are unique.
bool more_recent(const Observation& candidate, const Observation& incumbent) noexcept {
  if (candidate.quantity.sequence() != incumbent.quantity.sequence()) {
    return candidate.quantity.sequence() > incumbent.quantity.sequence();
  }
  if (candidate.observed_at != incumbent.observed_at) {
    return candidate.observed_at > incumbent.observed_at;
  }
  return candidate.id > incumbent.id;
}

}  // namespace

// ---------------------------------------------------------------------------
// Quantity
// ---------------------------------------------------------------------------

Result<Quantity> Quantity::observed(std::int64_t value, std::string_view unit, ObservationQuality quality,
                                    ObservationSequence sequence) {
  // A discrete state code carries no unit: a status channel reports 0 (normal),
  // 1 (degraded) or 2 (failed), and there is no physical unit to name. The empty
  // unit is accepted here and nowhere else - a declared bound still has to name
  // its unit (DeclaredQuantity::make), and a reading on a channel that has a
  // canonical unit still has to carry it (make_observation compares the two).
  //
  // The value of a unit-less reading is bounded by the state-code domain. A code
  // outside it is refused rather than interpreted, because the classification
  // reads "below 2" as not-failed: a negative or absurd code would silently
  // argue against a failure, which is exactly the inference this component
  // exists to prevent.
  if (unit.empty()) {
    if (value < 0 || value > kMaxStateCode) {
      return Error(ErrorCode::QuantityOutOfRange,
                   "a unit-less reading is a discrete state code and must be 0 (normal), 1 (degraded) "
                   "or 2 (failed)")
          .with_subject(std::to_string(value));
    }
    Quantity state_code;
    state_code.availability_ = Availability::Observed;
    state_code.quality_ = quality;
    state_code.sequence_ = sequence;
    state_code.value_ = value;
    return state_code;
  }

  // The accepted units and the per-unit numeric bounds live in exactly one
  // place: DeclaredQuantity::make. A reading and a declared bound carry the same
  // unit vocabulary with the same bounds, so a reading can never be accepted in
  // a unit no declared bound could use.
  auto declared = DeclaredQuantity::make(value, unit);
  if (!declared.has_value()) {
    return Error(declared.error().code(),
                 "observed quantity rejected: " + declared.error().message())
        .with_subject(declared.error().subject());
  }

  Quantity quantity;
  quantity.availability_ = Availability::Observed;
  quantity.quality_ = quality;
  quantity.sequence_ = sequence;
  quantity.value_ = value;
  quantity.unit_.assign(unit.data(), unit.size());
  return quantity;
}

Result<std::int64_t> Quantity::observed_value() const {
  if (availability_ != Availability::Observed) {
    // This is the central anti-inference rule of the component: an
    // indeterminate quantity carries no value, and substituting zero here would
    // turn "nobody told me" into "the flow is zero", which is a different and
    // far more dangerous statement.
    return Error(ErrorCode::EvidenceMissing,
                 "quantity is indeterminate: no reading exists, and no zero value is substituted for it");
  }
  return value_;
}

std::optional<std::int64_t> Quantity::value_if_observed() const noexcept {
  if (availability_ != Availability::Observed) {
    return std::nullopt;
  }
  return value_;
}

bool Quantity::is_usable() const noexcept {
  return availability_ == Availability::Observed &&
         (quality_ == ObservationQuality::Good || quality_ == ObservationQuality::Degraded);
}

bool observation_has_signal(const Observation& observation) noexcept {
  return observation.quantity.availability() == Availability::Observed;
}

bool observation_asserts_leak(const Observation& observation) noexcept {
  return observation.leak != LeakState::LeakUnknown;
}

// ---------------------------------------------------------------------------
// ObservationSet
// ---------------------------------------------------------------------------

Result<void> ObservationSet::add(const Observation& observation) {
  if (observation.id.empty()) {
    return Error(ErrorCode::MalformedIdentifier, "observation identity is empty");
  }
  if (observation.scope.empty()) {
    return Error(ErrorCode::MalformedIdentifier, "observation scope identity is empty")
        .with_subject(std::string(observation.id.value()));
  }
  for (const Observation& existing : observations_) {
    if (existing.id == observation.id) {
      return Error(ErrorCode::DuplicateIdentifier, "observation identity is already recorded in this set")
          .with_subject(std::string(observation.id.value()));
    }
  }
  if (observations_.size() >= limits::kMaxObservationCount) {
    return Error(ErrorCode::LimitExceeded, "observation set is at its capacity of " +
                                               std::to_string(limits::kMaxObservationCount) +
                                               " observations")
        .with_subject(std::string(observation.id.value()));
  }
  std::size_t per_scope = 0;
  for (const Observation& existing : observations_) {
    if (existing.scope == observation.scope) {
      ++per_scope;
    }
  }
  if (per_scope >= limits::kMaxObservationPerScope) {
    return Error(ErrorCode::LimitExceeded, "scope already holds " +
                                               std::to_string(limits::kMaxObservationPerScope) +
                                               " observations, which is the per-scope bound")
        .with_subject(std::string(observation.scope.value()));
  }
  observations_.push_back(observation);
  return ok();
}

Result<void> ObservationSet::add_all(const std::vector<Observation>& observations) {
  // The batch is validated in full against the current contents and against
  // itself before a single element is applied, so a refused batch leaves the set
  // exactly as it was. A half-applied batch would be an unrecorded state change
  // that no caller could reconcile.
  if (observations.empty()) {
    return ok();
  }
  if (observations.size() > limits::kMaxObservationCount - observations_.size()) {
    return Error(ErrorCode::LimitExceeded, "batch would exceed the observation set capacity of " +
                                               std::to_string(limits::kMaxObservationCount) +
                                               " observations");
  }

  std::set<std::string_view> identities;
  for (const Observation& existing : observations_) {
    identities.insert(existing.id.value());
  }
  std::map<std::string_view, std::size_t> per_scope;
  for (const Observation& existing : observations_) {
    ++per_scope[existing.scope.value()];
  }

  for (const Observation& observation : observations) {
    if (observation.id.empty()) {
      return Error(ErrorCode::MalformedIdentifier, "observation identity is empty in an added batch");
    }
    if (observation.scope.empty()) {
      return Error(ErrorCode::MalformedIdentifier,
                   "observation scope identity is empty in an added batch")
          .with_subject(std::string(observation.id.value()));
    }
    if (!identities.insert(observation.id.value()).second) {
      return Error(ErrorCode::DuplicateIdentifier,
                   "observation identity is already recorded, or appears twice in the added batch")
          .with_subject(std::string(observation.id.value()));
    }
    std::size_t& count = per_scope[observation.scope.value()];
    if (count >= limits::kMaxObservationPerScope) {
      return Error(ErrorCode::LimitExceeded, "scope would exceed the per-scope bound of " +
                                                 std::to_string(limits::kMaxObservationPerScope) +
                                                 " observations")
          .with_subject(std::string(observation.scope.value()));
    }
    ++count;
  }

  observations_.insert(observations_.end(), observations.begin(), observations.end());
  return ok();
}

std::vector<const Observation*> ObservationSet::for_scope(const ScopeId& scope) const {
  // The returned pointers borrow from this set: the caller must keep the set
  // alive for as long as it uses them. The set owns its observations and never
  // invalidates them except by destruction, because add() only appends and
  // sort_canonical() only permutes the vector.
  std::vector<const Observation*> matches;
  for (const Observation& observation : observations_) {
    if (observation.scope == scope) {
      matches.push_back(&observation);
    }
  }
  std::stable_sort(matches.begin(), matches.end(),
                   [](const Observation* lhs, const Observation* rhs) {
                     return canonical_order_less(*lhs, *rhs);
                   });
  return matches;
}

std::vector<const Observation*> ObservationSet::for_channel(const ScopeId& scope,
                                                            ObservationChannel channel) const {
  // Borrowed pointers, same contract as for_scope(). The order is the reverse of
  // the canonical one on purpose: the highest producer sequence comes first, so
  // a caller that only wants the newest observation of a channel reads the first
  // element, and ties fall back to the observation identity bytes.
  std::vector<const Observation*> matches;
  for (const Observation& observation : observations_) {
    if (observation.scope == scope && observation.channel == channel) {
      matches.push_back(&observation);
    }
  }
  std::stable_sort(matches.begin(), matches.end(),
                   [](const Observation* lhs, const Observation* rhs) {
                     if (lhs->quantity.sequence() != rhs->quantity.sequence()) {
                       return lhs->quantity.sequence() > rhs->quantity.sequence();
                     }
                     return lhs->id < rhs->id;
                   });
  return matches;
}

const Observation* ObservationSet::latest(const ScopeId& scope, ObservationChannel channel,
                                          const DecisionClock&, DurationMilliseconds) const {
  // The decision clock and the freshness window are deliberately not consulted
  // here. This function answers "which reading is the newest one I hold", not
  // "is that reading still current": the second question is answered by
  // assess_observation(), which keeps freshness, availability and quality as
  // separate facts. Filtering here would erase the difference between a channel
  // nobody ever reported on and a channel whose last report has aged out, and it
  // would hide a future-dated reading that the caller must be told about.
  //
  // An indeterminate quantity is a legitimate answer: an instrument that reports
  // nothing has still reported.
  const Observation* best = nullptr;
  for (const Observation& observation : observations_) {
    if (observation.scope != scope || observation.channel != channel) {
      continue;
    }
    if (best == nullptr || more_recent(observation, *best)) {
      best = &observation;
    }
  }
  return best;
}

std::vector<const Observation*> ObservationSet::since(const ScopeId& scope, ObservationChannel channel,
                                                      const DecisionClock& since_clock) const {
  std::vector<const Observation*> matches;
  for (const Observation& observation : observations_) {
    if (observation.scope == scope && observation.channel == channel &&
        observation.observed_at >= since_clock) {
      matches.push_back(&observation);
    }
  }
  std::stable_sort(matches.begin(), matches.end(),
                   [](const Observation* lhs, const Observation* rhs) {
                     if (lhs->quantity.sequence() != rhs->quantity.sequence()) {
                       return lhs->quantity.sequence() < rhs->quantity.sequence();
                     }
                     return lhs->id < rhs->id;
                   });
  return matches;
}

bool ObservationSet::has_conflict(const ScopeId& scope, ObservationChannel channel) const {
  std::vector<const Observation*> matches;
  for (const Observation& observation : observations_) {
    if (observation.scope == scope && observation.channel == channel) {
      matches.push_back(&observation);
    }
  }
  if (matches.size() < 2) {
    return false;
  }
  std::stable_sort(matches.begin(), matches.end(),
                   [](const Observation* lhs, const Observation* rhs) {
                     if (lhs->quantity.sequence() != rhs->quantity.sequence()) {
                       return lhs->quantity.sequence() < rhs->quantity.sequence();
                     }
                     return lhs->id < rhs->id;
                   });
  // Two producers that both claim the same sequence of the same channel are
  // reporting the same slot of the same stream. If they disagree about the slot,
  // there is no way to tell which one is the stream: the subject is Conflicting
  // and no reading on it may be used. Observations with different sequences are
  // not a conflict at all - one is simply older than the other. An absent
  // sequence (zero) is not a slot claim, so it cannot collide.
  for (std::size_t index = 1; index < matches.size(); ++index) {
    const Observation& previous = *matches[index - 1];
    const Observation& current = *matches[index];
    if (previous.quantity.sequence().value() == 0) {
      continue;
    }
    if (previous.quantity.sequence() == current.quantity.sequence() &&
        readings_differ(previous, current)) {
      return true;
    }
  }
  return false;
}

void ObservationSet::sort_canonical() {
  std::stable_sort(observations_.begin(), observations_.end(), canonical_order_less);
}

// ---------------------------------------------------------------------------
// Decision-time assessment
// ---------------------------------------------------------------------------

ObservationUsability assess_observation(const Observation* observation, const DecisionClock& clock,
                                        DurationMilliseconds window, bool conflicting) {
  ObservationUsability usability;
  if (observation == nullptr) {
    usability.status = EvidenceStatus::Missing;
    usability.freshness = Freshness::Unobserved;
    usability.age_milliseconds = 0;
    usability.detail = "no observation is recorded for this subject";
    return usability;
  }

  const std::int64_t observed_ms = observation->observed_at.milliseconds();
  const std::int64_t clock_ms = clock.milliseconds();
  const bool future_dated = observed_ms > clock_ms;

  // The age is a checked difference and is never clamped to zero: a reading
  // dated after the decision clock reports a negative age, and the caller must
  // see that instead of a comfortable zero. The only unrepresentable case is a
  // clock outside the range the library accepts from a caller, and even then the
  // reported age stays on the correct side of zero instead of wrapping.
  const std::optional<std::int64_t> difference = checked_difference(clock_ms, observed_ms);
  const std::int64_t age = difference.has_value() ? *difference : (future_dated ? INT64_MIN : INT64_MAX);
  usability.age_milliseconds = age;

  if (future_dated) {
    usability.freshness = Freshness::Future;
  } else if (difference.has_value() && age > window.milliseconds()) {
    usability.freshness = Freshness::Stale;
  } else if (!difference.has_value()) {
    usability.freshness = Freshness::Stale;
  } else {
    usability.freshness = Freshness::Current;
  }

  if (conflicting) {
    // Freshness is still reported, so an explanation can say both that two
    // streams disagree and how old the disagreement is.
    usability.status = EvidenceStatus::Conflicting;
    usability.detail = "two observations share a producer sequence but disagree about the reading";
    return usability;
  }

  if (usability.freshness == Freshness::Future) {
    usability.status = EvidenceStatus::Future;
    // The magnitude is taken in the direction that is positive, so reporting it
    // never negates a value that has no representable negation.
    const std::optional<std::int64_t> ahead = checked_difference(observed_ms, clock_ms);
    usability.detail = "the reading is dated after the decision clock by ";
    usability.detail += ahead.has_value() ? std::to_string(*ahead) + " ms"
                                          : std::string("more than the representable range");
    return usability;
  }

  if (usability.freshness == Freshness::Stale) {
    usability.status = EvidenceStatus::Stale;
    usability.detail = "the reading is older than the " + std::to_string(window.milliseconds()) +
                       " ms window";
    return usability;
  }

  // Freshness is Current from here on; the remaining checks decide whether the
  // reading may actually be used as evidence.
  //
  // The quality rules apply only when a reading exists. Quality is the producer's
  // claim about a reading it produced; an indeterminate quantity carries no
  // reading and therefore no claim, and its quality() is the no-claim default
  // rather than a judgement about a measurement. Reporting Indeterminate from
  // that default would also make a leak observation that asserts LeakNone
  // unusable, which is exactly the reading a leak gate needs.
  if (observation->quantity.has_value() &&
      observation->quantity.quality() == ObservationQuality::Bad) {
    usability.status = EvidenceStatus::Indeterminate;
    usability.detail = "the producer reports bad quality for this reading";
    return usability;
  }
  if (observation->quantity.has_value() &&
      observation->quantity.quality() == ObservationQuality::Suspect) {
    usability.status = EvidenceStatus::Indeterminate;
    usability.detail = "the producer reports suspect quality for this reading";
    return usability;
  }
  if (!observation_asserts_something(*observation)) {
    usability.status = EvidenceStatus::Indeterminate;
    usability.detail = is_scalar_channel(observation->channel)
                           ? "the channel carries no reading, so it asserts nothing"
                           : "the channel carries no state and no leak assertion";
    return usability;
  }
  if (!observation->evidence_generation.bound() && !is_status_only_channel(observation->channel)) {
    // A reading from an unversioned stream cannot be tied to the version of the
    // world it describes. A status-only channel is the documented exception: its
    // discrete state is the assertion itself, and there is no version of the
    // state to compare against.
    usability.status = EvidenceStatus::Unbound;
    usability.detail = "the reading carries no evidence generation";
    return usability;
  }

  usability.status = EvidenceStatus::Current;
  if (is_status_only_channel(observation->channel)) {
    usability.detail = "current status reading";
  } else if (channel_is_leak(observation->channel)) {
    usability.detail = "current leak reading";
  } else {
    usability.detail = "current reading";
  }
  return usability;
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

Result<void> validate_policy(const DecisionPolicy& policy) {
  // The exact rules, all of them about a demand the engine could not evaluate:
  //   * confirm_min_observations and suspect_min_observations are demands of at
  //     least one independent observation; zero would confirm or suspect every
  //     class from no evidence at all, so both are InvalidArgument;
  //   * healthy_min_observations is the same demand for a healthy verdict, and
  //     zero would report health from no evidence, which is the failure mode
  //     this whole component exists to prevent;
  //   * every window is a duration on the synthetic timeline and must be within
  //     [0, kMaxWindowMilliseconds]; a negative window is not a duration, and a
  //     window above the bound is refused rather than clamped.
  if (policy.confirm_min_observations == 0) {
    return Error(ErrorCode::InvalidArgument,
                 "confirm_min_observations must be at least 1: a class is never confirmed from no "
                 "independent observation");
  }
  if (policy.suspect_min_observations == 0) {
    return Error(ErrorCode::InvalidArgument,
                 "suspect_min_observations must be at least 1: a class is never suspected from no "
                 "independent observation");
  }
  if (policy.healthy_min_observations == 0) {
    return Error(ErrorCode::InvalidArgument,
                 "healthy_min_observations must be at least 1: health is never reported from no "
                 "independent observation");
  }
  if (policy.evidence_window.milliseconds() < 0) {
    return Error(ErrorCode::QuantityOutOfRange, "evidence_window must not be negative")
        .with_subject(std::to_string(policy.evidence_window.milliseconds()));
  }
  if (policy.evidence_window.milliseconds() > limits::kMaxWindowMilliseconds) {
    return Error(ErrorCode::QuantityOutOfRange,
                 "evidence_window exceeds the longest accepted window of " +
                     std::to_string(limits::kMaxWindowMilliseconds) + " ms")
        .with_subject(std::to_string(policy.evidence_window.milliseconds()));
  }
  if (policy.acknowledgement_window.milliseconds() < 0) {
    return Error(ErrorCode::QuantityOutOfRange, "acknowledgement_window must not be negative")
        .with_subject(std::to_string(policy.acknowledgement_window.milliseconds()));
  }
  if (policy.acknowledgement_window.milliseconds() > limits::kMaxWindowMilliseconds) {
    return Error(ErrorCode::QuantityOutOfRange,
                 "acknowledgement_window exceeds the longest accepted window of " +
                     std::to_string(limits::kMaxWindowMilliseconds) + " ms")
        .with_subject(std::to_string(policy.acknowledgement_window.milliseconds()));
  }
  if (static_cast<unsigned>(policy.safety_escalation_severity) > static_cast<unsigned>(Severity::Total)) {
    return Error(ErrorCode::UnknownEnumToken,
                 "safety_escalation_severity is not a severity this taxonomy declares");
  }
  return ok();
}

// ---------------------------------------------------------------------------
// Observation construction
// ---------------------------------------------------------------------------

Result<Observation> make_observation(const ObservationId& id, const ScopeId& scope,
                                     ObservationChannel channel, Quantity quantity, LeakState leak,
                                     const DecisionClock& observed_at, const DecisionClock& recorded_at,
                                     std::string_view producer, std::string_view sensor,
                                     EvidenceGeneration evidence_generation, bool carried_forward) {
  if (id.empty()) {
    return Error(ErrorCode::MalformedIdentifier, "observation identity is empty");
  }
  if (scope.empty()) {
    return Error(ErrorCode::MalformedIdentifier, "observation scope identity is empty")
        .with_subject(std::string(id.value()));
  }
  CFM_TRYV(require_external_identity(producer, limits::kMaxProducerBytes, "producer identity"));
  CFM_TRYV(require_external_identity(sensor, limits::kMaxSensorRefBytes, "sensor reference"));

  const std::int64_t observed_ms = observed_at.milliseconds();
  const std::int64_t recorded_ms = recorded_at.milliseconds();
  if (observed_ms < 0 || observed_ms > limits::kMaxTimestampMilliseconds) {
    return Error(ErrorCode::TimestampOutOfRange,
                 "sampling clock is outside [0, " + std::to_string(limits::kMaxTimestampMilliseconds) +
                     "] milliseconds")
        .with_subject(std::to_string(observed_ms));
  }
  if (recorded_ms < 0 || recorded_ms > limits::kMaxTimestampMilliseconds) {
    return Error(ErrorCode::TimestampOutOfRange,
                 "recording clock is outside [0, " + std::to_string(limits::kMaxTimestampMilliseconds) +
                     "] milliseconds")
        .with_subject(std::to_string(recorded_ms));
  }
  if (observed_ms > recorded_ms) {
    // An observation recorded before it was sampled is not a late arrival, it is
    // an impossible record: the recorder cannot have seen a sample that had not
    // been taken yet.
    return Error(ErrorCode::ObservationOutOfOrder,
                 "sampling clock is later than the recording clock")
        .with_subject(std::string(id.value()));
  }

  if (is_scalar_channel(channel)) {
    // A scalar channel has exactly one canonical unit. A reading carrying another
    // unit is refused rather than converted: this component never guesses an
    // exchange rate between units. An indeterminate quantity carries no unit and
    // is always acceptable, because a silent instrument is a legitimate record.
    if (quantity.has_value() && quantity.unit() != channel_unit(channel)) {
      return Error(ErrorCode::QuantityOutOfRange,
                   "reading unit disagrees with the channel's canonical unit")
          .with_subject(std::string(quantity.unit()));
    }
  }
  // A status channel carries the discrete state code as its reading, and a leak
  // channel carries a leak state; for both, a unit is optional and is never
  // compared against a canonical unit, because neither has one.

  if (channel_is_leak(channel) && leak == LeakState::LeakUnknown && !quantity.has_value()) {
    return Error(ErrorCode::EvidenceMissing,
                 "a leak observation must carry a leak state or a status reading")
        .with_subject(std::string(id.value()));
  }

  Observation observation;
  observation.id = id;
  observation.scope = scope;
  observation.channel = channel;
  observation.quantity = std::move(quantity);
  observation.leak = leak;
  observation.observed_at = observed_at;
  observation.recorded_at = recorded_at;
  observation.producer.assign(producer.data(), producer.size());
  observation.sensor.assign(sensor.data(), sensor.size());
  observation.evidence_generation = evidence_generation;
  observation.carried_forward = carried_forward;
  return observation;
}

}  // namespace dccp::cooling_failure_manager
