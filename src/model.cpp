// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/cooling_failure_manager/model.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dccp/cooling_failure_manager/classify.hpp"
#include "dccp/cooling_failure_manager/text.hpp"

namespace dccp::cooling_failure_manager {
namespace {

// ---------------------------------------------------------------------------
// Deriving the taxonomy bounds from the enumerations themselves
// ---------------------------------------------------------------------------
//
// Every enumeration below is contiguous from zero, so the value of its last
// enumerator plus one is its cardinality. Deriving the constants here rather
// than calling the *_count() helpers keeps this translation unit independent of
// their implementation, and the assertions pin the expected cardinality so a new
// enumerator fails the build instead of silently widening a bound.

inline constexpr std::size_t kScopeKindCount = static_cast<std::size_t>(ScopeKind::WorkloadScope) + 1u;
inline constexpr std::size_t kDependencyKindCount =
    static_cast<std::size_t>(DependencyKind::HousesHeatLoad) + 1u;
inline constexpr std::size_t kFailureClassCount =
    static_cast<std::size_t>(FailureClass::ThermalRunaway) + 1u;
inline constexpr std::size_t kConfirmationStateCount =
    static_cast<std::size_t>(ConfirmationState::Unsupported) + 1u;
inline constexpr std::size_t kSeverityCount = static_cast<std::size_t>(Severity::Total) + 1u;
inline constexpr std::size_t kUrgencyCount = static_cast<std::size_t>(Urgency::Immediate) + 1u;
inline constexpr std::size_t kTimeToImpactCount = static_cast<std::size_t>(TimeToImpact::Days) + 1u;
inline constexpr std::size_t kChannelCount =
    static_cast<std::size_t>(ObservationChannel::HumiditySensor) + 1u;
inline constexpr std::size_t kLeakStateCount = static_cast<std::size_t>(LeakState::LeakActive) + 1u;
inline constexpr std::size_t kEvidenceStatusCount = static_cast<std::size_t>(EvidenceStatus::Future) + 1u;
inline constexpr std::size_t kFreshnessCount = static_cast<std::size_t>(Freshness::Future) + 1u;
inline constexpr std::size_t kAvailabilityCount = static_cast<std::size_t>(Availability::Observed) + 1u;
inline constexpr std::size_t kObservationQualityCount =
    static_cast<std::size_t>(ObservationQuality::Bad) + 1u;
inline constexpr std::size_t kResponseActionCount =
    static_cast<std::size_t>(ResponseAction::ManualIntervention) + 1u;
inline constexpr std::size_t kEffectClassCount = static_cast<std::size_t>(EffectClass::LoadReduced) + 1u;
inline constexpr std::size_t kPlanLifecycleCount = static_cast<std::size_t>(PlanLifecycle::Withdrawn) + 1u;
inline constexpr std::size_t kAttemptStateCount = static_cast<std::size_t>(AttemptState::Withdrawn) + 1u;
inline constexpr std::size_t kRestrictionKindCount =
    static_cast<std::size_t>(RestrictionKind::ManualHold) + 1u;
inline constexpr std::size_t kRecoveryDecisionCount =
    static_cast<std::size_t>(RecoveryDecision::Permitted) + 1u;
inline constexpr std::size_t kBindingStatusCount =
    static_cast<std::size_t>(BindingStatus::Mismatched) + 1u;

static_assert(kScopeKindCount == 11, "a new ScopeKind needs a bound and a witness test");
static_assert(kDependencyKindCount == 6, "a new DependencyKind needs a canonical index");
static_assert(kFailureClassCount == 15, "a new FailureClass needs a rule row");
static_assert(kSeverityCount == 5, "a new Severity needs a bound");
static_assert(kChannelCount == 17, "a new ObservationChannel needs a canonical unit");
static_assert(kAttemptStateCount == 10, "a new AttemptState needs a lifecycle rule");

/// Bound on the number of bindings one AuthoritySet may hold. limits.hpp has no
/// dedicated binding bound; kMaxSolicitationCount (64) is the closest declared
/// bound for a small, fixed roster of named slots, and it is used here as the
/// documented choice. A binding set is a fixed roster of adjacent owners, never
/// a growing table, so the bound is deliberately small.
inline constexpr std::size_t kMaxAuthorityBindings = limits::kMaxSolicitationCount;

/// Bound on the channels a scope may require as evidence. Evidence requirements
/// are keyed by channel and duplicates are refused, so the channel count is the
/// tightest bound the taxonomy can give.
inline constexpr std::size_t kMaxEvidenceRequirements = kChannelCount;

// ---------------------------------------------------------------------------
// Units and their per-unit numeric bounds
// ---------------------------------------------------------------------------
//
// One row per unit this component understands, with the inclusive range a value
// in that unit may hold. A unit outside this table is rejected: the component
// never invents a unit and never converts between units.

struct UnitBound {
  std::string_view unit;
  std::int64_t minimum;
  std::int64_t maximum;
};

constexpr UnitBound kUnitBounds[] = {
    {"mL/s", -limits::kMaxFlowMillilitresPerSecond, limits::kMaxFlowMillilitresPerSecond},
    {"Pa", -limits::kMaxAbsolutePressurePascals, limits::kMaxAbsolutePressurePascals},
    {"mC", limits::kMinTemperatureMilliCelsius, limits::kMaxTemperatureMilliCelsius},
    {"W", 0, limits::kMaxThermalCapacityWatts},
    {"mK", limits::kMinThermalMarginMilliKelvin, limits::kMaxThermalMarginMilliKelvin},
    {"ppm", 0, limits::kMaxHumidityPartsPerMillion},
    {"Pa-dp", 0, limits::kMaxPressurePascals},
};

// ---------------------------------------------------------------------------
// Small validation helpers
// ---------------------------------------------------------------------------

/// Explains why an external identity was refused, with the code that names the
/// exact reason rather than one generic rejection: an absent field is
/// MissingField, an over-long field is TextTooLong, bytes that are not valid
/// UTF-8 are InvalidUtf8. The final branch is unreachable while
/// is_valid_external_identity() tests exactly those three conditions, and exists
/// so the function is total without depending on that implementation detail.
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

Result<void> require_enum_index(std::size_t index, std::size_t count, std::string_view what,
                                const std::string& subject) {
  if (index >= count) {
    return Error(ErrorCode::UnknownEnumToken,
                 std::string(what) + " is not a value this taxonomy declares")
        .with_subject(subject);
  }
  return ok();
}

Result<void> require_text_bound(const std::string& text, std::size_t max_bytes, std::string_view what,
                                const std::string& subject) {
  if (text.size() > max_bytes) {
    return Error(ErrorCode::TextTooLong,
                 std::string(what) + " exceeds the bound of " + std::to_string(max_bytes) + " bytes")
        .with_subject(subject);
  }
  return ok();
}

std::string class_subject(FailureClass failure_class) {
  return std::to_string(static_cast<unsigned>(failure_class));
}

std::string channel_subject(ObservationChannel channel) {
  return std::to_string(static_cast<unsigned>(channel));
}

std::size_t dependency_kind_index(DependencyKind kind) noexcept {
  return static_cast<std::size_t>(kind);
}

// ---------------------------------------------------------------------------
// Canonical orderings
// ---------------------------------------------------------------------------
//
// One definition per table, used both to sort (canonicalize) and to check
// (validate_structure). Sorting is by key only and is stable, so entries that
// share a key keep their relative order until the duplicate check refuses them;
// a state therefore never depends on the order a caller inserted its rows in.

bool scope_key_less(const CoolingScope& lhs, const CoolingScope& rhs) noexcept {
  return lhs.id < rhs.id;
}

bool dependency_key_less(const ScopeDependency& lhs, const ScopeDependency& rhs) noexcept {
  if (lhs.upstream != rhs.upstream) {
    return lhs.upstream < rhs.upstream;
  }
  return dependency_kind_index(lhs.kind) < dependency_kind_index(rhs.kind);
}

bool failure_class_less(FailureClass lhs, FailureClass rhs) noexcept {
  return static_cast<unsigned>(lhs) < static_cast<unsigned>(rhs);
}

bool requirement_key_less(const EvidenceRequirement& lhs, const EvidenceRequirement& rhs) noexcept {
  return channel_index(lhs.channel) < channel_index(rhs.channel);
}

bool failure_key_less(const CoolingFailure& lhs, const CoolingFailure& rhs) noexcept {
  return lhs.id < rhs.id;
}

bool observation_id_less(const ObservationId& lhs, const ObservationId& rhs) noexcept {
  return lhs < rhs;
}

bool failure_id_less(const FailureId& lhs, const FailureId& rhs) noexcept {
  return lhs < rhs;
}

bool plan_key_less(const ResponsePlan& lhs, const ResponsePlan& rhs) noexcept {
  return lhs.id < rhs.id;
}

bool eligibility_key_less(const ResponseEligibility& lhs, const ResponseEligibility& rhs) noexcept {
  if (lhs.rank != rhs.rank) {
    return lhs.rank < rhs.rank;
  }
  const std::size_t lhs_action = response_action_index(lhs.action);
  const std::size_t rhs_action = response_action_index(rhs.action);
  if (lhs_action != rhs_action) {
    return lhs_action < rhs_action;
  }
  return lhs.rule_id < rhs.rule_id;
}

bool restriction_key_less(const ProtectiveRestriction& lhs, const ProtectiveRestriction& rhs) noexcept {
  return lhs.id < rhs.id;
}

bool attempt_key_less(const ResponseAttempt& lhs, const ResponseAttempt& rhs) noexcept {
  if (lhs.solicitation != rhs.solicitation) {
    return lhs.solicitation < rhs.solicitation;
  }
  return lhs.attempt.value() < rhs.attempt.value();
}

bool evidence_key_less(const EvidenceAssessment& lhs, const EvidenceAssessment& rhs) noexcept {
  if (lhs.scope != rhs.scope) {
    return lhs.scope < rhs.scope;
  }
  const std::size_t lhs_channel = channel_index(lhs.channel);
  const std::size_t rhs_channel = channel_index(rhs.channel);
  if (lhs_channel != rhs_channel) {
    return lhs_channel < rhs_channel;
  }
  return lhs.observation < rhs.observation;
}

bool decision_key_less(const ScopeDecision& lhs, const ScopeDecision& rhs) noexcept {
  return lhs.scope < rhs.scope;
}

bool scope_id_less(const ScopeId& lhs, const ScopeId& rhs) noexcept { return lhs < rhs; }

bool restriction_id_less(const RestrictionId& lhs, const RestrictionId& rhs) noexcept {
  return lhs < rhs;
}

bool channel_less(ObservationChannel lhs, ObservationChannel rhs) noexcept {
  return channel_index(lhs) < channel_index(rhs);
}

bool attempt_id_less(const AttemptId& lhs, const AttemptId& rhs) noexcept { return lhs < rhs; }

// ---------------------------------------------------------------------------
// Canonicalization helpers
// ---------------------------------------------------------------------------

template <class T, class KeyLess, class Duplicate>
Result<void> canonicalize_table(std::vector<T>& table, KeyLess key_less, Duplicate duplicate) {
  if (table.size() > 1) {
    std::stable_sort(table.begin(), table.end(), key_less);
  }
  for (std::size_t index = 1; index < table.size(); ++index) {
    // Two entries are equivalent when neither orders before the other. Equal
    // keys are refused rather than merged: a state with two rows for one
    // identity has no single canonical encoding.
    if (!key_less(table[index - 1], table[index]) && !key_less(table[index], table[index - 1])) {
      return duplicate(table[index]);
    }
  }
  return ok();
}

template <class T, class KeyLess, class Duplicate>
Result<void> require_canonical_order(const std::vector<T>& table, KeyLess key_less, Duplicate duplicate,
                                     std::string_view what) {
  for (std::size_t index = 1; index < table.size(); ++index) {
    if (key_less(table[index], table[index - 1])) {
      return Error(ErrorCode::MalformedRecord,
                   std::string(what) +
                       " is not in canonical order; canonicalize() sorts every table before validation");
    }
    if (!key_less(table[index - 1], table[index])) {
      return duplicate(table[index]);
    }
  }
  return ok();
}

// ---------------------------------------------------------------------------
// Lookup helpers
// ---------------------------------------------------------------------------

/// Binary search over one canonical table keyed by identity bytes. The table must
/// be in canonical order, which canonicalize() establishes and validate_structure()
/// enforces for every state that enters the library; the lookup is then
/// deterministic and never depends on insertion order.
template <class T, class KeyOf>
const T* find_by_key(const std::vector<T>& table, std::string_view key, KeyOf key_of) noexcept {
  std::size_t low = 0;
  std::size_t high = table.size();
  while (low < high) {
    const std::size_t middle = low + (high - low) / 2;
    if (key_of(table[middle]) < key) {
      low = middle + 1;
    } else {
      high = middle;
    }
  }
  if (low < table.size() && key_of(table[low]) == key) {
    return &table[low];
  }
  return nullptr;
}

const ProtectiveRestriction* find_restriction(const CoolingFailureState& state, const ScopeId& scope,
                                              const RestrictionId& id) noexcept {
  // A restriction lives inside a plan, and plans are keyed by their own identity,
  // so the lookup walks the plan table in canonical order and returns the first
  // restriction of that scope carrying the identity.
  for (const ResponsePlan& plan : state.plans) {
    if (plan.scope != scope) {
      continue;
    }
    for (const ProtectiveRestriction& restriction : plan.restrictions) {
      if (restriction.id == id) {
        return &restriction;
      }
    }
  }
  return nullptr;
}

const EvidenceAssessment* find_evidence(const CoolingFailureState& state,
                                        const ObservationId& id) noexcept {
  // Evidence is keyed by (scope, channel, observation identity), so an identity
  // lookup is a scan. It is only used for the effect observations of verified and
  // refuted attempts, which are bounded by the attempt count.
  for (const EvidenceAssessment& entry : state.evidence) {
    if (entry.observation == id) {
      return &entry;
    }
  }
  return nullptr;
}

// ---------------------------------------------------------------------------
// Structural validation helpers
// ---------------------------------------------------------------------------

Result<void> validate_bindings(const AuthoritySet& bindings, std::string_view what) {
  if (bindings.size() > kMaxAuthorityBindings) {
    return Error(ErrorCode::LimitExceeded, std::string(what) + " holds more bindings than the bound of " +
                                               std::to_string(kMaxAuthorityBindings));
  }
  return ok();
}

Result<void> validate_declared_quantity(const DeclaredQuantity& quantity, std::string_view what,
                                        const std::string& subject) {
  if (!quantity.declared()) {
    // An undeclared bound is the documented way to say "this envelope declares
    // no limit here"; it is not an error, and it is never read as zero.
    return ok();
  }
  auto rebuilt = DeclaredQuantity::make(quantity.value(), quantity.unit());
  if (!rebuilt.has_value()) {
    return Error(rebuilt.error().code(), std::string(what) + " is not a usable declared quantity: " +
                                            rebuilt.error().message())
        .with_subject(subject);
  }
  return ok();
}

Result<void> validate_scope_policy(const CoolingScope& scope) {
  const std::string& subject = scope.id.str();
  const ScopePolicy& policy = scope.policy;

  CFM_TRYV(require_enum_index(static_cast<std::size_t>(policy.service_severity_floor), kSeverityCount,
                              "service severity floor", subject));
  CFM_TRYV(require_enum_index(static_cast<std::size_t>(scope.kind), kScopeKindCount, "scope kind",
                              subject));
  CFM_TRYV(require_text_bound(scope.display_name, limits::kMaxDisplayNameBytes, "scope display name",
                              subject));

  if (policy.requirements.size() > kMaxEvidenceRequirements) {
    return Error(ErrorCode::LimitExceeded,
                 "scope declares more evidence requirements than there are observation channels")
        .with_subject(subject);
  }
  CFM_TRYV(require_canonical_order(
      policy.requirements, requirement_key_less,
      [&subject](const EvidenceRequirement& requirement) {
        return Error(ErrorCode::DuplicateField, "the same channel is required twice as evidence")
            .with_subject(subject + ":" + channel_subject(requirement.channel));
      },
      "scope evidence requirements"));
  for (const EvidenceRequirement& requirement : policy.requirements) {
    CFM_TRYV(require_enum_index(channel_index(requirement.channel), kChannelCount, "required channel",
                                subject));
    if (requirement.window.milliseconds() < 0 ||
        requirement.window.milliseconds() > limits::kMaxWindowMilliseconds) {
      return Error(ErrorCode::QuantityOutOfRange,
                   "an evidence requirement window must be within [0, " +
                       std::to_string(limits::kMaxWindowMilliseconds) + "] milliseconds")
          .with_subject(subject + ":" + channel_subject(requirement.channel));
    }
  }

  if (policy.strict_classes.size() > kFailureClassCount) {
    return Error(ErrorCode::LimitExceeded, "scope declares more strict classes than there are classes")
        .with_subject(subject);
  }
  CFM_TRYV(require_canonical_order(
      policy.strict_classes, failure_class_less,
      [&subject](FailureClass failure_class) {
        return Error(ErrorCode::DuplicateFailureClass, "the same class is declared strict twice")
            .with_subject(subject + ":" + class_subject(failure_class));
      },
      "scope strict classes"));
  for (const FailureClass failure_class : policy.strict_classes) {
    CFM_TRYV(require_enum_index(failure_class_index(failure_class), kFailureClassCount,
                                "strict failure class", subject));
  }

  if (policy.recovery_dwell.milliseconds() < 0 ||
      policy.recovery_dwell.milliseconds() > limits::kMaxWindowMilliseconds) {
    return Error(ErrorCode::QuantityOutOfRange,
                 "recovery_dwell must be within [0, " +
                     std::to_string(limits::kMaxWindowMilliseconds) + "] milliseconds")
        .with_subject(subject);
  }
  if (policy.recovery_hysteresis.milliseconds() < 0 ||
      policy.recovery_hysteresis.milliseconds() > limits::kMaxWindowMilliseconds) {
    return Error(ErrorCode::QuantityOutOfRange,
                 "recovery_hysteresis must be within [0, " +
                     std::to_string(limits::kMaxWindowMilliseconds) + "] milliseconds")
        .with_subject(subject);
  }

  CFM_TRYV(validate_declared_quantity(policy.envelope.max_supply_temperature,
                                      "max_supply_temperature", subject));
  CFM_TRYV(validate_declared_quantity(policy.envelope.min_thermal_margin, "min_thermal_margin",
                                      subject));
  CFM_TRYV(validate_declared_quantity(policy.envelope.min_flow, "min_flow", subject));
  CFM_TRYV(validate_declared_quantity(policy.envelope.min_differential_pressure,
                                      "min_differential_pressure", subject));
  CFM_TRYV(validate_declared_quantity(policy.envelope.declared_demand, "declared_demand", subject));
  return ok();
}

/// Acyclicity of the scope dependency graph, with the depth of the search bounded
/// by limits::kMaxDependencyDepth. The traversal is iterative on purpose: a
/// recursive walk over untrusted input would consume the stack in proportion to
/// the graph, and a chain longer than the bound is reported as LimitExceeded
/// rather than explored.
Result<void> validate_scope_graph(const std::vector<CoolingScope>& scopes) {
  enum class Colour : std::uint8_t { White = 0, Grey = 1, Black = 2 };

  std::map<std::string_view, std::size_t> index_of;
  for (std::size_t index = 0; index < scopes.size(); ++index) {
    index_of.emplace(scopes[index].id.value(), index);
  }

  std::vector<Colour> colours(scopes.size(), Colour::White);
  // Each frame is (scope index, index of the next dependency to visit).
  std::vector<std::pair<std::size_t, std::size_t>> stack;
  std::vector<std::size_t> path;

  for (std::size_t root = 0; root < scopes.size(); ++root) {
    if (colours[root] != Colour::White) {
      continue;
    }
    stack.clear();
    path.clear();
    colours[root] = Colour::Grey;
    path.push_back(root);
    stack.emplace_back(root, 0);
    while (!stack.empty()) {
      const std::size_t current = stack.back().first;
      const CoolingScope& scope = scopes[current];
      std::size_t& next_dependency = stack.back().second;
      if (next_dependency >= scope.dependencies.size()) {
        colours[current] = Colour::Black;
        path.pop_back();
        stack.pop_back();
        continue;
      }
      const ScopeId& upstream = scope.dependencies[next_dependency].upstream;
      ++next_dependency;
      const auto found = index_of.find(upstream.value());
      if (found == index_of.end()) {
        // A missing upstream scope is reported by the dependency pass before the
        // graph is walked, so it is skipped here rather than reported twice.
        continue;
      }
      const std::size_t next = found->second;
      if (colours[next] == Colour::Grey) {
        const auto member = std::find(path.begin(), path.end(), next);
        Error error(ErrorCode::ScopeCycle, "the scope dependency graph contains a cycle");
        error.with_subject(scopes[next].id.str());
        for (auto it = member; it != path.end(); ++it) {
          error.with_detail("cycle-member=" + std::string(scopes[*it].id.value()));
        }
        error.with_detail("cycle-member=" + std::string(scopes[next].id.value()));
        return error;
      }
      if (colours[next] == Colour::Black) {
        continue;
      }
      if (path.size() >= limits::kMaxDependencyDepth) {
        return Error(ErrorCode::LimitExceeded,
                     "the scope dependency search exceeded the depth bound of " +
                         std::to_string(limits::kMaxDependencyDepth) + " scopes")
            .with_subject(scopes[next].id.str());
      }
      colours[next] = Colour::Grey;
      path.push_back(next);
      stack.emplace_back(next, 0);
    }
  }
  return ok();
}

Result<void> validate_scopes(const std::vector<CoolingScope>& scopes) {
  if (scopes.size() > limits::kMaxScopeCount) {
    return Error(ErrorCode::LimitExceeded, "the scope table exceeds the bound of " +
                                               std::to_string(limits::kMaxScopeCount) + " scopes");
  }
  CFM_TRYV(require_canonical_order(
      scopes, scope_key_less,
      [](const CoolingScope& scope) {
        return Error(ErrorCode::DuplicateIdentifier, "duplicate scope identity")
            .with_subject(scope.id.str());
      },
      "the scope table"));

  std::size_t dependency_total = 0;
  for (const CoolingScope& scope : scopes) {
    if (scope.id.empty()) {
      return Error(ErrorCode::MalformedIdentifier, "scope identity is empty");
    }
    CFM_TRYV(validate_scope_policy(scope));
    CFM_TRYV(validate_bindings(scope.bindings, "scope binding set"));

    if (scope.dependencies.size() > limits::kMaxScopeDependencyCount - dependency_total) {
      return Error(ErrorCode::LimitExceeded,
                   "the scope dependency table exceeds the bound of " +
                       std::to_string(limits::kMaxScopeDependencyCount) + " dependencies")
          .with_subject(scope.id.str());
    }
    dependency_total += scope.dependencies.size();

    CFM_TRYV(require_canonical_order(
        scope.dependencies, dependency_key_less,
        [&scope](const ScopeDependency& dependency) {
          return Error(ErrorCode::DuplicateField,
                       "the same upstream scope and dependency kind appear twice")
              .with_subject(scope.id.str() + ":" + std::string(dependency.upstream.value()));
        },
        "a scope dependency list"));
    for (const ScopeDependency& dependency : scope.dependencies) {
      if (dependency.upstream.empty()) {
        return Error(ErrorCode::MalformedIdentifier, "dependency upstream identity is empty")
            .with_subject(scope.id.str());
      }
      if (dependency.upstream == scope.id) {
        return Error(ErrorCode::ScopeCycle, "a scope declares a dependency on itself")
            .with_subject(scope.id.str());
      }
      const bool upstream_exists =
          find_by_key(scopes, dependency.upstream.value(),
                      [](const CoolingScope& candidate) { return candidate.id.value(); }) != nullptr;
      if (!upstream_exists) {
        return Error(ErrorCode::ScopeNotFound, "dependency names an upstream scope that is not declared")
            .with_subject(scope.id.str() + ":" + std::string(dependency.upstream.value()));
      }
      if (dependency.share_parts_per_million < 0 || dependency.share_parts_per_million > 1000000) {
        // A share is parts per million of the downstream scope's cooling, so it
        // is a fraction of a whole and can neither be negative nor exceed it.
        return Error(ErrorCode::QuantityOutOfRange,
                     "a dependency share must be within [0, 1000000] parts per million")
            .with_subject(scope.id.str() + ":" + std::string(dependency.upstream.value()));
      }
    }
  }
  return validate_scope_graph(scopes);
}

Result<void> validate_failures(const CoolingFailureState& state) {
  const std::vector<CoolingFailure>& failures = state.failures;
  if (failures.size() > limits::kMaxFailureCount) {
    return Error(ErrorCode::LimitExceeded, "the failure table exceeds the bound of " +
                                               std::to_string(limits::kMaxFailureCount) + " failures");
  }
  CFM_TRYV(require_canonical_order(
      failures, failure_key_less,
      [](const CoolingFailure& failure) {
        return Error(ErrorCode::FailureDuplicate, "duplicate failure identity")
            .with_subject(failure.id.str());
      },
      "the failure table"));

  for (const CoolingFailure& failure : failures) {
    const std::string& subject = failure.id.str();
    if (failure.id.empty()) {
      return Error(ErrorCode::MalformedIdentifier, "failure identity is empty");
    }
    if (failure.scope.empty() || find_scope(state, failure.scope) == nullptr) {
      return Error(ErrorCode::ScopeNotFound, "failure names a scope that is not declared")
          .with_subject(subject);
    }
    CFM_TRYV(require_enum_index(failure_class_index(failure.failure_class), kFailureClassCount,
                                "failure class", subject));
    CFM_TRYV(require_enum_index(static_cast<std::size_t>(failure.confirmation), kConfirmationStateCount,
                                "confirmation state", subject));
    CFM_TRYV(require_enum_index(static_cast<std::size_t>(failure.severity), kSeverityCount,
                                "failure severity", subject));
    CFM_TRYV(require_enum_index(static_cast<std::size_t>(failure.urgency), kUrgencyCount,
                                "failure urgency", subject));
    CFM_TRYV(require_enum_index(static_cast<std::size_t>(failure.time_to_impact), kTimeToImpactCount,
                                "time to impact", subject));
    CFM_TRYV(require_text_bound(failure.rationale, limits::kMaxTextBytes, "failure rationale", subject));

    if (failure.basis.size() > limits::kMaxDecisionEntryCount) {
      return Error(ErrorCode::LimitExceeded, "a failure cites more basis observations than the bound of " +
                                                 std::to_string(limits::kMaxDecisionEntryCount))
          .with_subject(subject);
    }
    CFM_TRYV(require_canonical_order(
        failure.basis, observation_id_less,
        [&subject](const ObservationId& id) {
          return Error(ErrorCode::DuplicateIdentifier, "the same observation is cited twice as basis")
              .with_subject(subject + ":" + id.str());
        },
        "a failure basis list"));
    for (const ObservationId& id : failure.basis) {
      if (id.empty()) {
        return Error(ErrorCode::MalformedIdentifier, "failure basis identity is empty")
            .with_subject(subject);
      }
    }
    if (!failure.shared_source.empty() && find_scope(state, failure.shared_source) == nullptr) {
      return Error(ErrorCode::ScopeNotFound, "failure names a shared source that is not declared")
          .with_subject(subject);
    }
  }
  return ok();
}

Result<void> validate_attempt(const ResponseAttempt& attempt, const ResponsePlan& plan,
                              const CoolingFailureState& state) {
  const std::string& subject = attempt.id.str();
  if (attempt.id.empty()) {
    return Error(ErrorCode::MalformedIdentifier, "attempt identity is empty");
  }
  if (attempt.solicitation.empty()) {
    return Error(ErrorCode::MalformedIdentifier, "attempt solicitation identity is empty")
        .with_subject(subject);
  }
  if (attempt.attempt.value() == 0) {
    return Error(ErrorCode::InvalidArgument, "attempt ordinal is 1-based and must not be zero")
        .with_subject(subject);
  }
  CFM_TRYV(require_enum_index(response_action_index(attempt.action), kResponseActionCount,
                              "attempt action", subject));
  CFM_TRYV(require_enum_index(static_cast<std::size_t>(attempt.effect_class), kEffectClassCount,
                              "attempt effect class", subject));
  CFM_TRYV(require_enum_index(static_cast<std::size_t>(attempt.state), kAttemptStateCount,
                              "attempt state", subject));
  CFM_TRYV(require_text_bound(attempt.verdict, limits::kMaxTextBytes, "attempt verdict", subject));
  if (!attempt.addressee.empty()) {
    CFM_TRYV(require_external_identity(attempt.addressee, limits::kMaxExternalIdentityBytes,
                                       "attempt addressee"));
  }

  // An effect claim needs the observation that carries it. A state that says an
  // effect was verified without naming the evidence for it is exactly the
  // collapse this component refuses: acknowledgement, observed effect and
  // verified effect are three separate facts.
  if (attempt.state == AttemptState::Verified || attempt.state == AttemptState::Refuted) {
    if (attempt.effect_observation.empty() || attempt.verdict.empty()) {
      return Error(ErrorCode::EffectClaimedWithoutEvidence,
                   attempt.state == AttemptState::Verified
                       ? "a verified attempt must name its effect observation and its verdict"
                       : "a refuted attempt must name the observation that refuted it and its verdict")
          .with_subject(subject);
    }
    const EvidenceAssessment* evidence = find_evidence(state, attempt.effect_observation);
    if (evidence == nullptr) {
      return Error(ErrorCode::EffectClaimedWithoutEvidence,
                   "the effect observation of this attempt is not recorded in the evidence table")
          .with_subject(subject + ":" + attempt.effect_observation.str());
    }
    if (evidence->scope != plan.scope) {
      return Error(ErrorCode::EffectClaimedWithoutEvidence,
                   "the effect observation of this attempt belongs to another scope")
          .with_subject(subject + ":" + attempt.effect_observation.str());
    }
  }

  // Acknowledgement is its own fact with its own clock. An attempt that was never
  // solicited cannot have been answered, and an attempt that was answered must
  // say when, so a caller can tell "no reply" from "a reply we did not date".
  const bool acknowledges = attempt.state == AttemptState::Acknowledged ||
                            attempt.state == AttemptState::EffectObserved ||
                            attempt.state == AttemptState::Verified;
  if (attempt.state == AttemptState::Planned && attempt.acknowledged_at.present()) {
    return Error(ErrorCode::AcknowledgementInvalid,
                 "a planned attempt must not carry an acknowledgement clock")
        .with_subject(subject);
  }
  if (acknowledges && !attempt.acknowledged_at.present()) {
    return Error(ErrorCode::AcknowledgementInvalid,
                 "an acknowledged, effect-observed or verified attempt must carry an acknowledgement "
                 "clock")
        .with_subject(subject);
  }
  return ok();
}

Result<void> validate_plans(const CoolingFailureState& state) {
  const std::vector<ResponsePlan>& plans = state.plans;
  // At most one plan per scope is useful, so the scope bound is the plan table's
  // bound. The identity itself is still unique and checked below.
  if (plans.size() > limits::kMaxScopeCount) {
    return Error(ErrorCode::LimitExceeded, "the plan table exceeds the bound of " +
                                               std::to_string(limits::kMaxScopeCount) + " plans");
  }
  CFM_TRYV(require_canonical_order(
      plans, plan_key_less,
      [](const ResponsePlan& plan) {
        return Error(ErrorCode::PlanDuplicate, "duplicate plan identity").with_subject(plan.id.str());
      },
      "the plan table"));

  // A restriction identity is an identity of the whole state, not of one plan, so
  // it is checked across every plan. The scan is bounded by the plan and
  // restriction bounds.
  std::vector<std::string_view> restriction_ids;
  std::vector<std::string_view> attempt_ids;

  for (const ResponsePlan& plan : plans) {
    const std::string& subject = plan.id.str();
    if (plan.id.empty()) {
      return Error(ErrorCode::MalformedIdentifier, "plan identity is empty");
    }
    if (plan.scope.empty() || find_scope(state, plan.scope) == nullptr) {
      return Error(ErrorCode::ScopeNotFound, "plan names a scope that is not declared")
          .with_subject(subject);
    }
    CFM_TRYV(require_enum_index(static_cast<std::size_t>(plan.lifecycle), kPlanLifecycleCount,
                                "plan lifecycle", subject));
    CFM_TRYV(require_enum_index(response_action_index(plan.solicited_action), kResponseActionCount,
                                "solicited action", subject));
    CFM_TRYV(require_text_bound(plan.explanation, limits::kMaxTextBytes, "plan explanation", subject));

    CFM_TRYV(require_canonical_order(
        plan.failures, failure_id_less,
        [&subject](const FailureId& id) {
          return Error(ErrorCode::FailureDuplicate, "the same failure is answered twice by one plan")
              .with_subject(subject + ":" + id.str());
        },
        "a plan failure list"));
    for (const FailureId& id : plan.failures) {
      const CoolingFailure* failure = find_failure(state, id);
      if (failure == nullptr) {
        return Error(ErrorCode::FailureNotFound, "plan answers a failure that is not declared")
            .with_subject(subject + ":" + id.str());
      }
      if (failure->scope != plan.scope) {
        return Error(ErrorCode::ScopeKindMismatch,
                     "plan answers a failure that belongs to another scope")
            .with_subject(subject + ":" + id.str());
      }
    }

    if (plan.eligible.size() > limits::kMaxPlanEligibilityCount) {
      return Error(ErrorCode::LimitExceeded, "a plan lists more eligible actions than the bound of " +
                                                 std::to_string(limits::kMaxPlanEligibilityCount))
          .with_subject(subject);
    }
    CFM_TRYV(require_canonical_order(
        plan.eligible, eligibility_key_less,
        [&subject](const ResponseEligibility& eligible) {
          return Error(ErrorCode::DuplicateField, "the same eligible action is listed twice")
              .with_subject(subject + ":" + std::to_string(response_action_index(eligible.action)));
        },
        "a plan eligibility list"));
    for (const ResponseEligibility& eligible : plan.eligible) {
      CFM_TRYV(require_enum_index(response_action_index(eligible.action), kResponseActionCount,
                                  "eligible action", subject));
      CFM_TRYV(require_enum_index(static_cast<std::size_t>(eligible.effect_class), kEffectClassCount,
                                  "eligible effect class", subject));
      CFM_TRYV(require_text_bound(eligible.rule_id, limits::kMaxTextBytes, "eligibility rule identity",
                                  subject));
    }

    if (plan.restrictions.size() > limits::kMaxRestrictionCount) {
      return Error(ErrorCode::LimitExceeded, "a plan carries more restrictions than the bound of " +
                                                 std::to_string(limits::kMaxRestrictionCount))
          .with_subject(subject);
    }
    CFM_TRYV(require_canonical_order(
        plan.restrictions, restriction_key_less,
        [&subject](const ProtectiveRestriction& restriction) {
          return Error(ErrorCode::DuplicateIdentifier, "duplicate restriction identity in one plan")
              .with_subject(subject + ":" + restriction.id.str());
        },
        "a plan restriction list"));
    for (const ProtectiveRestriction& restriction : plan.restrictions) {
      const std::string restriction_subject = subject + ":" + restriction.id.str();
      if (restriction.id.empty()) {
        return Error(ErrorCode::MalformedIdentifier, "restriction identity is empty")
            .with_subject(subject);
      }
      for (const std::string_view seen : restriction_ids) {
        if (seen == restriction.id.value()) {
          return Error(ErrorCode::DuplicateIdentifier,
                       "the same restriction identity appears in more than one plan")
              .with_subject(restriction.id.str());
        }
      }
      restriction_ids.push_back(restriction.id.value());

      if (restriction.scope.empty() || find_scope(state, restriction.scope) == nullptr) {
        return Error(ErrorCode::ScopeNotFound, "restriction names a scope that is not declared")
            .with_subject(restriction_subject);
      }
      if (restriction.scope != plan.scope) {
        return Error(ErrorCode::ScopeKindMismatch,
                     "restriction scope does not match the scope of the plan that carries it")
            .with_subject(restriction_subject);
      }
      const ResponsePlan* owner =
          find_by_key(state.plans, restriction.plan.value(),
                      [](const ResponsePlan& candidate) { return candidate.id.value(); });
      if (owner == nullptr) {
        return Error(ErrorCode::PlanNotFound, "restriction names a plan that is not declared")
            .with_subject(restriction_subject);
      }
      if (owner->scope != restriction.scope) {
        return Error(ErrorCode::ScopeKindMismatch,
                     "restriction names a plan of another scope")
            .with_subject(restriction_subject);
      }
      CFM_TRYV(require_enum_index(restriction_kind_index(restriction.kind), kRestrictionKindCount,
                                  "restriction kind", restriction_subject));
      CFM_TRYV(validate_declared_quantity(restriction.ceiling, "restriction ceiling",
                                          restriction_subject));
      CFM_TRYV(require_canonical_order(
          restriction.released_by, failure_id_less,
          [&restriction_subject](const FailureId& id) {
            return Error(ErrorCode::FailureDuplicate,
                         "the same failure releases a restriction twice")
                .with_subject(restriction_subject + ":" + id.str());
          },
          "a restriction release list"));
      for (const FailureId& id : restriction.released_by) {
        const CoolingFailure* failure = find_failure(state, id);
        if (failure == nullptr) {
          return Error(ErrorCode::FailureNotFound, "restriction names a releasing failure that is not declared")
              .with_subject(restriction_subject + ":" + id.str());
        }
        if (failure->scope != restriction.scope) {
          return Error(ErrorCode::ScopeKindMismatch,
                       "restriction is released by a failure of another scope")
              .with_subject(restriction_subject + ":" + id.str());
        }
      }
    }

    if (plan.attempts.size() > limits::kMaxAttemptCount) {
      return Error(ErrorCode::LimitExceeded, "a plan carries more attempts than the bound of " +
                                                 std::to_string(limits::kMaxAttemptCount))
          .with_subject(subject);
    }
    CFM_TRYV(require_canonical_order(
        plan.attempts, attempt_key_less,
        [&subject](const ResponseAttempt& attempt) {
          return Error(ErrorCode::AttemptDuplicate,
                       "the same solicitation identity and ordinal appear twice in one plan")
              .with_subject(subject + ":" + attempt.id.str());
        },
        "a plan attempt list"));
    for (const ResponseAttempt& attempt : plan.attempts) {
      for (const std::string_view seen : attempt_ids) {
        if (seen == attempt.id.value()) {
          return Error(ErrorCode::AttemptDuplicate,
                       "the same attempt identity appears in more than one plan")
              .with_subject(attempt.id.str());
        }
      }
      attempt_ids.push_back(attempt.id.value());
      CFM_TRYV(validate_attempt(attempt, plan, state));
    }
  }
  return ok();
}

Result<void> validate_evidence(const CoolingFailureState& state) {
  const std::vector<EvidenceAssessment>& evidence = state.evidence;
  if (evidence.size() > limits::kMaxObservationCount) {
    return Error(ErrorCode::LimitExceeded, "the evidence table exceeds the bound of " +
                                               std::to_string(limits::kMaxObservationCount) +
                                               " observations");
  }
  CFM_TRYV(require_canonical_order(
      evidence, evidence_key_less,
      [](const EvidenceAssessment& entry) {
        return Error(ErrorCode::DuplicateIdentifier,
                     "duplicate evidence record for one scope, channel and observation")
            .with_subject(entry.observation.str());
      },
      "the evidence table"));

  std::size_t run_count = 0;
  const ScopeId* run_scope = nullptr;
  for (const EvidenceAssessment& entry : evidence) {
    if (entry.observation.empty()) {
      return Error(ErrorCode::MalformedIdentifier, "evidence observation identity is empty");
    }
    if (entry.scope.empty() || find_scope(state, entry.scope) == nullptr) {
      return Error(ErrorCode::ScopeNotFound, "evidence names a scope that is not declared")
          .with_subject(entry.observation.str());
    }
    CFM_TRYV(require_enum_index(channel_index(entry.channel), kChannelCount, "evidence channel",
                                entry.observation.str()));
    CFM_TRYV(require_enum_index(static_cast<std::size_t>(entry.status), kEvidenceStatusCount,
                                "evidence status", entry.observation.str()));
    CFM_TRYV(require_enum_index(static_cast<std::size_t>(entry.freshness), kFreshnessCount,
                                "evidence freshness", entry.observation.str()));
    CFM_TRYV(require_enum_index(static_cast<std::size_t>(entry.availability), kAvailabilityCount,
                                "evidence availability", entry.observation.str()));
    CFM_TRYV(require_enum_index(static_cast<std::size_t>(entry.quality), kObservationQualityCount,
                                "evidence quality", entry.observation.str()));
    CFM_TRYV(require_text_bound(entry.detail, limits::kMaxTextBytes, "evidence detail",
                                entry.observation.str()));

    // Current evidence that was never observed is a contradiction: Unobserved
    // means no observation has ever been recorded, which can never be Current.
    if (entry.status == EvidenceStatus::Current && entry.freshness == Freshness::Unobserved) {
      return Error(ErrorCode::EvidenceNotCurrent,
                   "evidence is marked Current while its freshness is Unobserved")
          .with_subject(entry.observation.str());
    }

    if (run_scope == nullptr || entry.scope != *run_scope) {
      run_scope = &entry.scope;
      run_count = 0;
    }
    ++run_count;
    if (run_count > limits::kMaxObservationPerScope) {
      return Error(ErrorCode::LimitExceeded, "one scope holds more evidence records than the bound of " +
                                                 std::to_string(limits::kMaxObservationPerScope))
          .with_subject(entry.scope.str());
    }
  }

  // One observation is one record: the same identity must not be assessed twice
  // under different scopes or channels.
  if (evidence.size() > 1) {
    std::vector<std::string_view> identities;
    identities.reserve(evidence.size());
    for (const EvidenceAssessment& entry : evidence) {
      identities.push_back(entry.observation.value());
    }
    std::sort(identities.begin(), identities.end());
    for (std::size_t index = 1; index < identities.size(); ++index) {
      if (identities[index] == identities[index - 1]) {
        return Error(ErrorCode::DuplicateIdentifier,
                     "the same observation identity appears twice in the evidence table")
            .with_subject(std::string(identities[index]));
      }
    }
  }
  return ok();
}

Result<void> validate_decision(const ScopeDecision& decision, const CoolingFailureState& state) {
  const std::string& subject = decision.scope.str();
  if (decision.scope.empty()) {
    return Error(ErrorCode::MalformedIdentifier, "decision scope identity is empty");
  }
  if (find_scope(state, decision.scope) == nullptr) {
    return Error(ErrorCode::ScopeNotFound, "decision names a scope that is not declared")
        .with_subject(subject);
  }
  CFM_TRYV(require_enum_index(static_cast<std::size_t>(decision.severity), kSeverityCount,
                              "decision severity", subject));
  CFM_TRYV(require_enum_index(static_cast<std::size_t>(decision.urgency), kUrgencyCount,
                              "decision urgency", subject));
  CFM_TRYV(require_enum_index(static_cast<std::size_t>(decision.time_to_impact), kTimeToImpactCount,
                              "decision time to impact", subject));
  CFM_TRYV(require_enum_index(static_cast<std::size_t>(decision.binding_status), kBindingStatusCount,
                              "decision binding status", subject));
  CFM_TRYV(require_enum_index(static_cast<std::size_t>(decision.plan_lifecycle), kPlanLifecycleCount,
                              "decision plan lifecycle", subject));
  CFM_TRYV(require_enum_index(static_cast<std::size_t>(decision.recovery), kRecoveryDecisionCount,
                              "decision recovery", subject));
  if (decision.explanation.size() > limits::kMaxDecisionEntryCount) {
    return Error(ErrorCode::LimitExceeded, "a decision carries more explanation lines than the bound of " +
                                               std::to_string(limits::kMaxDecisionEntryCount))
        .with_subject(subject);
  }
  for (const std::string& line : decision.explanation) {
    CFM_TRYV(require_text_bound(line, limits::kMaxTextBytes, "decision explanation line", subject));
  }

  // The four class buckets are pairwise disjoint, each sorted and duplicate-free:
  // a class is confirmed, suspected, contradicted or unknown, never two of them.
  bool classified[kFailureClassCount] = {};
  const std::vector<FailureClass>* buckets[] = {&decision.confirmed_classes,
                                                &decision.suspected_classes,
                                                &decision.contradicted_classes,
                                                &decision.unknown_classes};
  const std::size_t bucket_bound[] = {limits::kMaxConfirmedClassesPerScope, kFailureClassCount,
                                      kFailureClassCount, kFailureClassCount};
  for (std::size_t bucket = 0; bucket < 4; ++bucket) {
    const std::vector<FailureClass>& classes = *buckets[bucket];
    if (classes.size() > bucket_bound[bucket]) {
      return Error(ErrorCode::LimitExceeded, "a decision class bucket exceeds its bound")
          .with_subject(subject);
    }
    CFM_TRYV(require_canonical_order(
        classes, failure_class_less,
        [&subject](FailureClass failure_class) {
          return Error(ErrorCode::DuplicateFailureClass,
                       "the same class appears twice in one classification bucket")
              .with_subject(subject + ":" + class_subject(failure_class));
        },
        "a decision class bucket"));
    for (const FailureClass failure_class : classes) {
      CFM_TRYV(require_enum_index(failure_class_index(failure_class), kFailureClassCount,
                                  "classified failure class", subject));
      if (classified[failure_class_index(failure_class)]) {
        return Error(ErrorCode::FailureClassConflict,
                     "a class appears in more than one classification bucket")
            .with_subject(subject + ":" + class_subject(failure_class));
      }
      classified[failure_class_index(failure_class)] = true;
    }
  }

  if (decision.failures.size() > limits::kMaxDecisionEntryCount) {
    return Error(ErrorCode::LimitExceeded, "a decision lists more failures than the bound of " +
                                               std::to_string(limits::kMaxDecisionEntryCount))
        .with_subject(subject);
  }
  CFM_TRYV(require_canonical_order(
      decision.failures, failure_id_less,
      [&subject](const FailureId& id) {
        return Error(ErrorCode::FailureDuplicate, "the same failure is listed twice by one decision")
            .with_subject(subject + ":" + id.str());
      },
      "a decision failure list"));
  Severity maximum = Severity::None;
  for (const FailureId& id : decision.failures) {
    const CoolingFailure* failure = find_failure(state, id);
    if (failure == nullptr) {
      return Error(ErrorCode::FailureNotFound, "decision lists a failure that is not declared")
          .with_subject(subject + ":" + id.str());
    }
    if (failure->scope != decision.scope) {
      return Error(ErrorCode::ScopeKindMismatch,
                   "decision lists a failure that belongs to another scope")
          .with_subject(subject + ":" + id.str());
    }
    if (static_cast<unsigned>(failure->severity) > static_cast<unsigned>(maximum)) {
      maximum = failure->severity;
    }
  }
  // The severity of a decision is the maximum severity over the failures that
  // justify it: a decision may not understate the failures it lists, and it may
  // not invent a severity no listed failure carries.
  if (!decision.failures.empty() && decision.severity != maximum) {
    return Error(ErrorCode::FailureClassConflict,
                 "decision severity is not the maximum severity of the failures it lists")
        .with_subject(subject);
  }

  if (decision.shared_sources.size() > limits::kMaxSharedSourceCount) {
    return Error(ErrorCode::LimitExceeded, "a decision names more shared sources than the bound of " +
                                               std::to_string(limits::kMaxSharedSourceCount))
        .with_subject(subject);
  }
  CFM_TRYV(require_canonical_order(
      decision.shared_sources, scope_id_less,
      [&subject](const ScopeId& id) {
        return Error(ErrorCode::DuplicateIdentifier, "the same shared source is listed twice")
            .with_subject(subject + ":" + id.str());
      },
      "a decision shared source list"));
  for (const ScopeId& id : decision.shared_sources) {
    if (id.empty() || find_scope(state, id) == nullptr) {
      return Error(ErrorCode::ScopeNotFound, "decision names a shared source that is not declared")
          .with_subject(subject + ":" + id.str());
    }
  }

  if (decision.restrictions.size() > limits::kMaxRestrictionCount) {
    return Error(ErrorCode::LimitExceeded, "a decision lists more restrictions than the bound of " +
                                               std::to_string(limits::kMaxRestrictionCount))
        .with_subject(subject);
  }
  CFM_TRYV(require_canonical_order(
      decision.restrictions, restriction_id_less,
      [&subject](const RestrictionId& id) {
        return Error(ErrorCode::DuplicateIdentifier, "the same restriction is listed twice")
            .with_subject(subject + ":" + id.str());
      },
      "a decision restriction list"));
  for (const RestrictionId& id : decision.restrictions) {
    if (id.empty() || find_restriction(state, decision.scope, id) == nullptr) {
      return Error(ErrorCode::RestrictionNotFound,
                   "decision names a restriction that is not in force for its scope")
          .with_subject(subject + ":" + id.str());
    }
  }

  if (decision.evidence_gaps.size() > limits::kMaxEvidenceGapCount) {
    return Error(ErrorCode::LimitExceeded, "a decision reports more evidence gaps than the bound of " +
                                               std::to_string(limits::kMaxEvidenceGapCount))
        .with_subject(subject);
  }
  CFM_TRYV(require_canonical_order(
      decision.evidence_gaps, channel_less,
      [&subject](ObservationChannel channel) {
        return Error(ErrorCode::DuplicateField, "the same channel is reported as a gap twice")
            .with_subject(subject + ":" + channel_subject(channel));
      },
      "a decision evidence gap list"));
  for (const ObservationChannel channel : decision.evidence_gaps) {
    CFM_TRYV(require_enum_index(channel_index(channel), kChannelCount, "evidence gap channel", subject));
  }

  if (decision.has_plan) {
    const ResponsePlan* plan = find_by_key(state.plans, decision.plan.value(),
                                           [](const ResponsePlan& candidate) {
                                             return candidate.id.value();
                                           });
    if (decision.plan.empty() || plan == nullptr) {
      return Error(ErrorCode::PlanNotFound, "decision names a plan that is not declared")
          .with_subject(subject + ":" + decision.plan.str());
    }
    if (plan->scope != decision.scope) {
      return Error(ErrorCode::ScopeKindMismatch, "decision names a plan of another scope")
          .with_subject(subject + ":" + decision.plan.str());
    }
  }
  return ok();
}

Result<void> validate_decisions(const CoolingFailureState& state) {
  const std::vector<ScopeDecision>& decisions = state.decisions;
  if (decisions.size() > limits::kMaxScopeCount) {
    return Error(ErrorCode::LimitExceeded, "the decision table exceeds the bound of " +
                                               std::to_string(limits::kMaxScopeCount) + " decisions");
  }
  CFM_TRYV(require_canonical_order(
      decisions, decision_key_less,
      [](const ScopeDecision& decision) {
        return Error(ErrorCode::DuplicateIdentifier, "duplicate decision for one scope")
            .with_subject(decision.scope.str());
      },
      "the decision table"));
  for (const ScopeDecision& decision : decisions) {
    CFM_TRYV(validate_decision(decision, state));
  }
  return ok();
}

Result<void> validate_unresolved_attempts(const CoolingFailureState& state) {
  const std::vector<AttemptId>& unresolved = state.unresolved_attempts;
  if (unresolved.size() > limits::kMaxAttemptSetCount) {
    return Error(ErrorCode::LimitExceeded, "the unresolved attempt list exceeds the bound of " +
                                               std::to_string(limits::kMaxAttemptSetCount));
  }
  CFM_TRYV(require_canonical_order(
      unresolved, attempt_id_less,
      [](const AttemptId& id) {
        return Error(ErrorCode::AttemptDuplicate, "the same unresolved attempt is listed twice")
            .with_subject(id.str());
      },
      "the unresolved attempt list"));
  for (const AttemptId& id : unresolved) {
    if (id.empty()) {
      return Error(ErrorCode::MalformedIdentifier, "unresolved attempt identity is empty");
    }
    const ResponseAttempt* attempt = find_attempt(state, id);
    if (attempt == nullptr) {
      return Error(ErrorCode::AttemptNotFound, "unresolved attempt is not present in any plan")
          .with_subject(id.str());
    }
    if (attempt->state != AttemptState::Unresolved) {
      return Error(ErrorCode::AttemptNotResolvable,
                   "an attempt that is not in the Unresolved state must not be listed as unresolved")
          .with_subject(id.str());
    }
  }
  return ok();
}

}  // namespace

// ---------------------------------------------------------------------------
// AuthorityRef
// ---------------------------------------------------------------------------

Result<AuthorityRef> AuthorityRef::make(std::string_view owner, std::string_view identity,
                                        ExternalGeneration generation) {
  CFM_TRYV(require_external_identity(owner, limits::kMaxExternalKindBytes, "binding owner"));
  CFM_TRYV(require_external_identity(identity, limits::kMaxExternalIdentityBytes, "binding identity"));
  if (!generation.bound()) {
    // A binding names one version of a fact owned by another component. A
    // generation of zero names no version, so the binding could never be checked
    // for staleness and would silently become a permanent claim.
    return Error(ErrorCode::GenerationMismatch,
                 "a binding must name the generation it was made against; generation 0 names no "
                 "version");
  }
  AuthorityRef reference;
  reference.owner_.assign(owner.data(), owner.size());
  reference.identity_.assign(identity.data(), identity.size());
  reference.generation_ = generation;
  return reference;
}

std::strong_ordering operator<=>(const AuthorityRef& lhs, const AuthorityRef& rhs) noexcept {
  if (const std::strong_ordering by_owner = lhs.owner_ <=> rhs.owner_; by_owner != 0) {
    return by_owner;
  }
  if (const std::strong_ordering by_identity = lhs.identity_ <=> rhs.identity_; by_identity != 0) {
    return by_identity;
  }
  return lhs.generation_.value() <=> rhs.generation_.value();
}

// ---------------------------------------------------------------------------
// AuthoritySet
// ---------------------------------------------------------------------------

Result<void> AuthoritySet::set(std::string_view role, AuthorityRef reference) {
  if (role.empty()) {
    return Error(ErrorCode::MissingField, "binding role must not be empty");
  }
  if (role.size() > limits::kMaxExternalKindBytes) {
    return Error(ErrorCode::TextTooLong, "binding role exceeds the bound of " +
                                             std::to_string(limits::kMaxExternalKindBytes) + " bytes")
        .with_subject(std::string(role.substr(0, 64)));
  }
  if (!is_ascii_token(role)) {
    // A role is a stable ASCII token, and it is the key of the binding set. A
    // role that is not a token could carry whitespace, a path separator or a
    // look-alike into an encoding that is used for identification.
    return Error(ErrorCode::MalformedIdentifier,
                 "binding role must be an ASCII token of [0-9A-Za-z._:-]")
        .with_subject(std::string(role.substr(0, 64)));
  }

  // The entries are kept sorted by (role, owner, identity) so encoding never
  // depends on the order a caller supplied bindings in. The role is unique in the
  // set: setting a role replaces the binding held for it, because two answers for
  // one role would leave the decision bound to a version nobody chose.
  std::size_t position = 0;
  while (position < entries_.size() && entries_[position].first < role) {
    ++position;
  }
  if (position == entries_.size() || entries_[position].first != role) {
    if (entries_.size() >= kMaxAuthorityBindings) {
      return Error(ErrorCode::LimitExceeded,
                   "the binding set already holds the maximum of " +
                       std::to_string(kMaxAuthorityBindings) + " roles")
          .with_subject(std::string(role));
    }
    entries_.insert(entries_.begin() + static_cast<std::ptrdiff_t>(position),
                    std::make_pair(std::string(role), std::move(reference)));
    return ok();
  }
  entries_[position].second = std::move(reference);
  return ok();
}

void AuthoritySet::erase(std::string_view role) {
  for (std::size_t position = 0; position < entries_.size(); ++position) {
    if (entries_[position].first == role) {
      entries_.erase(entries_.begin() + static_cast<std::ptrdiff_t>(position));
      return;
    }
  }
  // An absent role is not an error: erasing a binding that is not held leaves the
  // set exactly as the caller asked for it.
}

const AuthorityRef* AuthoritySet::find(std::string_view role) const noexcept {
  std::size_t low = 0;
  std::size_t high = entries_.size();
  while (low < high) {
    const std::size_t middle = low + (high - low) / 2;
    if (entries_[middle].first < role) {
      low = middle + 1;
    } else {
      high = middle;
    }
  }
  if (low < entries_.size() && entries_[low].first == role) {
    return &entries_[low].second;
  }
  return nullptr;
}

bool operator==(const AuthoritySet& lhs, const AuthoritySet& rhs) noexcept {
  // Exact equality over the canonical ordering: two binding sets are equal only
  // when they hold the same roles, bound to the same owner, identity and
  // generation. Nothing about a binding is approximate.
  return lhs.entries_ == rhs.entries_;
}

// ---------------------------------------------------------------------------
// DeclaredQuantity
// ---------------------------------------------------------------------------

Result<DeclaredQuantity> DeclaredQuantity::make(std::int64_t value, std::string_view unit) {
  CFM_TRYV(require_external_identity(unit, limits::kMaxExternalKindBytes, "quantity unit"));

  const UnitBound* bound = nullptr;
  for (const UnitBound& candidate : kUnitBounds) {
    if (candidate.unit == unit) {
      bound = &candidate;
      break;
    }
  }
  if (bound == nullptr) {
    // An unknown unit is refused rather than assumed: this component never
    // invents a unit and never converts between units, so a value in a unit it
    // does not understand has no comparable meaning at all.
    return Error(ErrorCode::QuantityOutOfRange, "unknown quantity unit").with_subject(std::string(unit));
  }
  if (value < bound->minimum || value > bound->maximum) {
    return Error(ErrorCode::QuantityOutOfRange,
                 "quantity in " + std::string(unit) + " must be within [" +
                     std::to_string(bound->minimum) + ", " + std::to_string(bound->maximum) + "]")
        .with_subject(std::to_string(value));
  }

  DeclaredQuantity quantity;
  quantity.value_ = value;
  quantity.unit_.assign(unit.data(), unit.size());
  return quantity;
}

std::strong_ordering operator<=>(const DeclaredQuantity& lhs, const DeclaredQuantity& rhs) noexcept {
  // (unit, value) is a canonical order, not a physical comparison: two declared
  // quantities in different units are ordered by their unit bytes, and this
  // component never claims that one is larger than the other. Only quantities in
  // the same unit are compared arithmetically.
  if (const std::strong_ordering by_unit = lhs.unit_ <=> rhs.unit_; by_unit != 0) {
    return by_unit;
  }
  return lhs.value_ <=> rhs.value_;
}

// ---------------------------------------------------------------------------
// Canonicalization
// ---------------------------------------------------------------------------

Result<void> canonicalize(CoolingFailureState& state) {
  // The canonical orders, one line per table:
  //   scopes              by scope identity bytes
  //   dependencies        by (upstream identity, dependency kind index)
  //   strict classes      by failure class index
  //   evidence reqs       by channel index
  //   AuthoritySet        by (role, owner, identity) - maintained by every mutation
  //   failures            by failure identity bytes
  //   basis               by observation identity bytes
  //   plans               by plan identity bytes
  //   plan failures       by failure identity bytes
  //   eligible            by (rank, action index, rule identity bytes)
  //   restrictions        by restriction identity bytes
  //   released_by         by failure identity bytes
  //   attempts            by (solicitation identity bytes, attempt ordinal)
  //   evidence            by (scope identity bytes, channel index, observation identity bytes)
  //   decisions           by scope identity bytes
  //   decision buckets    by failure class index
  //   decision failures   by failure identity bytes
  //   shared sources      by scope identity bytes
  //   decision restricts  by restriction identity bytes
  //   evidence gaps       by channel index
  //   explanation         left exactly as produced
  //   unresolved attempts by attempt identity bytes
  // Canonicalizing twice changes nothing: every table is sorted by its key with a
  // stable sort, so a second pass finds it already ordered and the duplicate scan
  // finds no equal key.

  CFM_TRYV(canonicalize_table(state.scopes, scope_key_less, [](const CoolingScope& scope) {
    return Error(ErrorCode::DuplicateIdentifier, "duplicate scope identity").with_subject(scope.id.str());
  }));
  for (CoolingScope& scope : state.scopes) {
    CFM_TRYV(canonicalize_table(
        scope.dependencies, dependency_key_less, [&scope](const ScopeDependency& dependency) {
          return Error(ErrorCode::DuplicateField,
                       "the same upstream scope and dependency kind appear twice")
              .with_subject(scope.id.str() + ":" + std::string(dependency.upstream.value()));
        }));
    CFM_TRYV(canonicalize_table(
        scope.policy.strict_classes, failure_class_less, [&scope](FailureClass failure_class) {
          return Error(ErrorCode::DuplicateFailureClass, "the same class is declared strict twice")
              .with_subject(scope.id.str() + ":" + class_subject(failure_class));
        }));
    CFM_TRYV(canonicalize_table(
        scope.policy.requirements, requirement_key_less, [&scope](const EvidenceRequirement& item) {
          return Error(ErrorCode::DuplicateField, "the same channel is required twice as evidence")
              .with_subject(scope.id.str() + ":" + channel_subject(item.channel));
        }));
  }

  CFM_TRYV(canonicalize_table(state.failures, failure_key_less, [](const CoolingFailure& failure) {
    return Error(ErrorCode::FailureDuplicate, "duplicate failure identity")
        .with_subject(failure.id.str());
  }));
  for (CoolingFailure& failure : state.failures) {
    CFM_TRYV(canonicalize_table(
        failure.basis, observation_id_less, [&failure](const ObservationId& id) {
          return Error(ErrorCode::DuplicateIdentifier, "the same observation is cited twice as basis")
              .with_subject(failure.id.str() + ":" + id.str());
        }));
  }

  CFM_TRYV(canonicalize_table(state.plans, plan_key_less, [](const ResponsePlan& plan) {
    return Error(ErrorCode::PlanDuplicate, "duplicate plan identity").with_subject(plan.id.str());
  }));
  for (ResponsePlan& plan : state.plans) {
    CFM_TRYV(canonicalize_table(plan.failures, failure_id_less, [&plan](const FailureId& id) {
      return Error(ErrorCode::FailureDuplicate, "the same failure is answered twice by one plan")
          .with_subject(plan.id.str() + ":" + id.str());
    }));
    CFM_TRYV(canonicalize_table(
        plan.eligible, eligibility_key_less, [&plan](const ResponseEligibility& eligible) {
          return Error(ErrorCode::DuplicateField, "the same eligible action is listed twice")
              .with_subject(plan.id.str() + ":" +
                            std::to_string(response_action_index(eligible.action)));
        }));
    CFM_TRYV(canonicalize_table(
        plan.restrictions, restriction_key_less, [&plan](const ProtectiveRestriction& restriction) {
          return Error(ErrorCode::DuplicateIdentifier, "duplicate restriction identity in one plan")
              .with_subject(plan.id.str() + ":" + restriction.id.str());
        }));
    for (ProtectiveRestriction& restriction : plan.restrictions) {
      CFM_TRYV(canonicalize_table(
          restriction.released_by, failure_id_less, [&restriction](const FailureId& id) {
            return Error(ErrorCode::FailureDuplicate,
                         "the same failure releases a restriction twice")
                .with_subject(restriction.id.str() + ":" + id.str());
          }));
    }
    CFM_TRYV(canonicalize_table(plan.attempts, attempt_key_less, [&plan](const ResponseAttempt& attempt) {
      return Error(ErrorCode::AttemptDuplicate,
                   "the same solicitation identity and ordinal appear twice in one plan")
          .with_subject(plan.id.str() + ":" + attempt.id.str());
    }));
  }

  CFM_TRYV(canonicalize_table(state.evidence, evidence_key_less, [](const EvidenceAssessment& entry) {
    return Error(ErrorCode::DuplicateIdentifier,
                 "duplicate evidence record for one scope, channel and observation")
        .with_subject(entry.observation.str());
  }));

  CFM_TRYV(canonicalize_table(state.decisions, decision_key_less, [](const ScopeDecision& decision) {
    return Error(ErrorCode::DuplicateIdentifier, "duplicate decision for one scope")
        .with_subject(decision.scope.str());
  }));
  for (ScopeDecision& decision : state.decisions) {
    const auto reject_class = [&decision](FailureClass failure_class) {
      return Error(ErrorCode::DuplicateFailureClass,
                   "the same class appears twice in one classification bucket")
          .with_subject(decision.scope.str() + ":" + class_subject(failure_class));
    };
    CFM_TRYV(canonicalize_table(decision.confirmed_classes, failure_class_less, reject_class));
    CFM_TRYV(canonicalize_table(decision.suspected_classes, failure_class_less, reject_class));
    CFM_TRYV(canonicalize_table(decision.contradicted_classes, failure_class_less, reject_class));
    CFM_TRYV(canonicalize_table(decision.unknown_classes, failure_class_less, reject_class));
    CFM_TRYV(canonicalize_table(
        decision.failures, failure_id_less, [&decision](const FailureId& id) {
          return Error(ErrorCode::FailureDuplicate, "the same failure is listed twice by one decision")
              .with_subject(decision.scope.str() + ":" + id.str());
        }));
    CFM_TRYV(canonicalize_table(
        decision.shared_sources, scope_id_less, [&decision](const ScopeId& id) {
          return Error(ErrorCode::DuplicateIdentifier, "the same shared source is listed twice")
              .with_subject(decision.scope.str() + ":" + id.str());
        }));
    CFM_TRYV(canonicalize_table(
        decision.restrictions, restriction_id_less, [&decision](const RestrictionId& id) {
          return Error(ErrorCode::DuplicateIdentifier, "the same restriction is listed twice")
              .with_subject(decision.scope.str() + ":" + id.str());
        }));
    CFM_TRYV(canonicalize_table(
        decision.evidence_gaps, channel_less, [&decision](ObservationChannel channel) {
          return Error(ErrorCode::DuplicateField, "the same channel is reported as a gap twice")
              .with_subject(decision.scope.str() + ":" + channel_subject(channel));
        }));
    // decision.explanation is the engine's canonical output, already in the order
    // it must be read in. Sorting it here would rewrite the engine's statement.
  }

  CFM_TRYV(canonicalize_table(
      state.unresolved_attempts, attempt_id_less, [](const AttemptId& id) {
        return Error(ErrorCode::AttemptDuplicate, "the same unresolved attempt is listed twice")
            .with_subject(id.str());
      }));
  return ok();
}

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------
//
// Every lookup below assumes the state is in canonical order. That is the
// documented precondition: canonicalize() establishes the order and
// validate_structure() rejects a state that is not in it, so every state that
// enters the library through a public entry point satisfies it. A caller that
// hand-builds a state must canonicalize it before looking anything up; a lookup
// never falls back to insertion order, because that would make the answer depend
// on how the state was assembled.

const CoolingScope* find_scope(const CoolingFailureState& state, const ScopeId& id) noexcept {
  return find_by_key(state.scopes, id.value(),
                     [](const CoolingScope& scope) { return scope.id.value(); });
}

const CoolingFailure* find_failure(const CoolingFailureState& state, const FailureId& id) noexcept {
  return find_by_key(state.failures, id.value(),
                     [](const CoolingFailure& failure) { return failure.id.value(); });
}

CoolingFailure* find_failure(CoolingFailureState& state, const FailureId& id) noexcept {
  return const_cast<CoolingFailure*>(find_failure(static_cast<const CoolingFailureState&>(state), id));
}

const ResponsePlan* find_plan(const CoolingFailureState& state, const PlanId& id) noexcept {
  return find_by_key(state.plans, id.value(),
                     [](const ResponsePlan& plan) { return plan.id.value(); });
}

ResponsePlan* find_plan(CoolingFailureState& state, const PlanId& id) noexcept {
  return const_cast<ResponsePlan*>(find_plan(static_cast<const CoolingFailureState&>(state), id));
}

const ResponsePlan* find_plan_for_scope(const CoolingFailureState& state, const ScopeId& scope) noexcept {
  // Plans are keyed by their own identity, not by scope, so this is a linear scan
  // over the canonical plan order. It returns the first plan in that order, which
  // is deterministic even if a state holds more than one plan for a scope.
  for (const ResponsePlan& plan : state.plans) {
    if (plan.scope == scope) {
      return &plan;
    }
  }
  return nullptr;
}

const ResponseAttempt* find_attempt(const CoolingFailureState& state, const AttemptId& id) noexcept {
  // Attempts are ordered by (solicitation identity, ordinal) rather than by their
  // own identity, so an identity lookup is a scan: plans in canonical order, then
  // each plan's attempts in canonical order.
  for (const ResponsePlan& plan : state.plans) {
    for (const ResponseAttempt& attempt : plan.attempts) {
      if (attempt.id == id) {
        return &attempt;
      }
    }
  }
  return nullptr;
}

const ScopeDecision* find_decision(const CoolingFailureState& state, const ScopeId& scope) noexcept {
  return find_by_key(state.decisions, scope.value(),
                     [](const ScopeDecision& decision) { return decision.scope.value(); });
}

// ---------------------------------------------------------------------------
// Structural validation
// ---------------------------------------------------------------------------
//
// Ordering is part of the contract. Every table is required to be in the
// canonical order canonicalize() produces and the canonical encoder emits, so a
// state that is not canonical is rejected here instead of being silently
// re-sorted: validate_structure() is also the check the strict decoder runs on
// untrusted bytes, and a second spelling of a state that already has a canonical
// one must not be accepted. The tables are validated in the order they are
// encoded - bindings, scopes, failures, plans, evidence, decisions, unresolved
// attempts - so the reported error is the canonical first one for a state.
//
// Clock ranges are deliberately not re-checked here. Every clock enters the
// library through DecisionClock::parse() or make_observation(), both of which
// bound it, and the strict decoder bounds it again on the way in; re-checking
// would not add a guarantee, while the two clock rules that are structural - the
// acknowledgement rule of an attempt and the Current/freshness rule of an
// evidence entry - are validated below because they state what the state means
// rather than what range a number is in.

Result<void> validate_structure(const CoolingFailureState& state) {
  CFM_TRYV(validate_bindings(state.bindings, "state binding set"));
  CFM_TRYV(validate_scopes(state.scopes));
  CFM_TRYV(validate_failures(state));
  CFM_TRYV(validate_plans(state));
  CFM_TRYV(validate_evidence(state));
  CFM_TRYV(validate_decisions(state));
  CFM_TRYV(validate_unresolved_attempts(state));
  return ok();
}

}  // namespace dccp::cooling_failure_manager
