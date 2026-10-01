// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_COOLING_FAILURE_MANAGER_CLASSIFY_HPP
#define DCCP_COOLING_FAILURE_MANAGER_CLASSIFY_HPP

#include <cstdint>
#include <string_view>

#include "dccp/cooling_failure_manager/enums.hpp"
#include "dccp/cooling_failure_manager/model.hpp"
#include "dccp/cooling_failure_manager/result.hpp"

namespace dccp::cooling_failure_manager {

/// What a single reading on a witness channel means for one failure class.
///
/// The signal is the whole classification vocabulary of this component. It is
/// deliberately coarse: this library decides *whether* a read channel is inside
/// or outside the envelope its owner declared. It never computes a capacity, a
/// flow balance, a heat budget or a load forecast, because those belong to
/// Cooling Capacity and Cooling Topology.
enum class NullSignal : std::uint8_t {
  /// The class has no witness on this channel; the channel is supporting only.
  None = 0,
  /// The reading is at or below the declared floor on this channel.
  BelowDeclaredFloor = 1,
  /// The reading is at or above the declared ceiling on this channel.
  AboveDeclaredCeiling = 2,
  /// The reading is outside the declared envelope on either side.
  OutsideDeclaredEnvelope = 3,
  /// The reading is zero, i.e. the channel is positively dead.
  Dead = 4,
  /// The status channel positively reports the failed condition.
  StatusFailed = 5,
  /// The status channel positively reports the failed condition and the class is
  /// a partial degradation rather than a loss.
  StatusDegraded = 6,
  /// The leak state on this channel is at or above the class's leak threshold.
  LeakPresent = 7,
};

/// Whether one channel witnesses a class directly, supports a suspicion, or
/// only argues against the class.
enum class WitnessRole : std::uint8_t {
  /// A positive reading on this channel, in the class's direction, can confirm
  /// the class when the policy allows direct witnesses.
  Direct = 0,
  /// A reading on this channel can raise a suspicion but never confirms.
  Supporting = 1,
  /// A healthy reading on this channel argues against the class but cannot by
  /// itself establish health.
  Refuting = 2,
};

/// One channel's role in one class's classification rule.
struct ChannelWitness {
  ObservationChannel channel = ObservationChannel::FlowMeter;
  WitnessRole role = WitnessRole::Supporting;
  /// The signal that indicates this class on this channel.
  NullSignal signal = NullSignal::None;
  /// For LeakPresent: the leak state at or above which the channel witnesses.
  LeakState leak_threshold = LeakState::LeakSuspected;
};

/// The complete rule for one failure class.
///
/// The table is a compile-time constant, published through failure_rule(), so
/// that classification is inspectable, reproducible and reviewable rather than
/// implicit in control flow.
struct FailureRule {
  FailureClass failure_class = FailureClass::LoopLoss;
  /// Severity this class carries when confirmed.
  Severity severity = Severity::Impaired;
  /// Urgency this class carries when confirmed.
  Urgency urgency = Urgency::Elevated;
  /// Interval in which a scope with this class is expected to exhaust its
  /// thermal capacity.
  TimeToImpact time_to_impact = TimeToImpact::Hours;
  /// True when the class describes a whole-function loss rather than a
  /// degradation.
  bool total_loss = false;
  /// True when a confirmed class forces a protective restriction regardless of
  /// the scope's service severity floor.
  bool forces_restriction = false;
  /// True when a confirmed class may be responded to immediately, without
  /// waiting for the dwell windows that a recovery waits for.
  bool safety_escalation = false;
  /// Witness channels, in canonical channel order.
  ChannelWitness witnesses[4]{};
  std::size_t witness_count = 0;
  /// True when the class may only be confirmed from a direct witness. This is
  /// the class's own requirement and is ANDed with the policy's.
  bool requires_direct_witness = true;
  /// Stable identifier of the rule, used in explanations.
  std::string_view rule_id;
};

/// The rule for one class. Never null.
const FailureRule& failure_rule(FailureClass failure_class) noexcept;

/// The signal a reading on a channel produces for a class, given the scope's
/// declared envelope.
struct WitnessReading {
  /// The class's witness for this channel, or nullptr when the channel is not a
  /// witness for the class.
  const ChannelWitness* witness = nullptr;
  /// True when the reading satisfies the class's signal on this channel.
  bool triggered = false;
  /// True when the reading exists, is usable, and clearly does *not* satisfy the
  /// signal, i.e. it argues against the class.
  bool contradicting = false;
};

/// Reads the envelope-bound signal for a channel against the declared envelope.
/// Envelope-bound witnesses (BelowDeclaredFloor, AboveDeclaredCeiling,
/// OutsideDeclaredEnvelope, Dead) need the scope's declared bounds, which this
/// function takes explicitly so the rule table stays a pure constant.
struct WitnessInputs {
  /// Observed value, when the channel supplied one.
  std::int64_t value = 0;
  bool has_value = false;
  /// Declared floor for this channel, when the envelope declares one.
  std::int64_t declared_floor = 0;
  bool has_floor = false;
  /// Declared ceiling for this channel, when the envelope declares one.
  std::int64_t declared_ceiling = 0;
  bool has_ceiling = false;
  /// Declared thermal demand, when the envelope declares one.
  std::int64_t declared_demand = 0;
  bool has_demand = false;
  /// Leak state carried by the observation.
  LeakState leak = LeakState::LeakUnknown;
  /// True when the reading is usable as evidence.
  bool usable = false;
};

/// Evaluates one channel reading against one class rule.
/// Returns a WitnessReading whose witness is null when the channel is not a
/// witness for the class.
WitnessReading evaluate_witness(FailureClass failure_class, ObservationChannel channel,
                                const WitnessInputs& inputs) noexcept;

/// The declared floor a channel's envelope supplies, when it declares one.
struct EnvelopeBound {
  bool has_floor = false;
  std::int64_t floor_value = 0;
  std::string_view floor_unit;
  bool has_ceiling = false;
  std::int64_t ceiling_value = 0;
  std::string_view ceiling_unit;
};

/// Extracts the declared envelope bound a channel carries. A channel with no
/// declared bound returns an empty bound, and every envelope-bound witness on
/// that channel then reports Unsupported rather than guessing a limit.
EnvelopeBound envelope_bound_for(const ScopePolicy& policy, ObservationChannel channel) noexcept;

/// Extracts the declared scalar the channel's witness should be compared with,
/// together with the channel's canonical unit.
struct ChannelThreshold {
  bool has_threshold = false;
  std::int64_t threshold = 0;
  std::string_view unit;
};

/// The declared threshold for a channel: a floor for flow, differential
/// pressure, thermal margin and thermal capacity; a ceiling for supply
/// temperature.
ChannelThreshold channel_threshold(const ScopePolicy& policy, ObservationChannel channel) noexcept;

/// The canonical unit of one channel.
std::string_view channel_unit(ObservationChannel channel) noexcept;

/// True when the channel carries a leak assertion rather than a scalar.
bool channel_is_leak(ObservationChannel channel) noexcept;

/// Channel order index used for canonical ordering.
std::size_t channel_index(ObservationChannel channel) noexcept;

/// Class order index used for canonical ordering.
std::size_t failure_class_index(FailureClass failure_class) noexcept;
std::size_t response_action_index(ResponseAction action) noexcept;
std::size_t recovery_gate_index(RecoveryGate gate) noexcept;
std::size_t restriction_kind_index(RestrictionKind kind) noexcept;

}  // namespace dccp::cooling_failure_manager

#endif  // DCCP_COOLING_FAILURE_MANAGER_CLASSIFY_HPP
