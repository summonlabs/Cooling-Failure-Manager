// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// cfmctl - the Cooling Failure Manager inspection and evaluation tool.
//
// The tool has two jobs. It renders durable state so an operator can read the
// authoritative cooling-failure answer for a scope, and it turns a synthetic
// scenario file into a decision, optionally publishing it. It never actuates
// anything: every response it reports is a bounded request recorded against a
// decision, and every recovery verdict it prints is a gate evaluation over
// evidence the scenario supplied.
//
// Exit codes:
//   0  the command succeeded;
//   1  the command ran but the answer is negative (a failed verification, a
//      blocked recovery, a refused publication);
//   2  the command line itself was wrong;
//   3  the input could not be read or decoded.
//
// The scenario file format is line oriented and documented in the README. Lines
// are stripped of surrounding whitespace, a '#' starts a comment, a blank line is
// ignored, and a 'key = value' pair belongs to the section that is currently open
// or is global when no section is open.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dccp/cooling_failure_manager/canonical.hpp"
#include "dccp/cooling_failure_manager/classify.hpp"
#include "dccp/cooling_failure_manager/decision.hpp"
#include "dccp/cooling_failure_manager/digest.hpp"
#include "dccp/cooling_failure_manager/enums.hpp"
#include "dccp/cooling_failure_manager/evidence.hpp"
#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/model.hpp"
#include "dccp/cooling_failure_manager/recovery.hpp"
#include "dccp/cooling_failure_manager/result.hpp"
#include "dccp/cooling_failure_manager/store.hpp"
#include "dccp/cooling_failure_manager/text.hpp"
#include "dccp/cooling_failure_manager/version.hpp"

namespace cfm = dccp::cooling_failure_manager;


namespace {

constexpr int kExitOk = 0;
constexpr int kExitNegative = 1;
constexpr int kExitUsage = 2;
constexpr int kExitInput = 3;

/// The largest scenario file this tool accepts. It is a bound on the input this
/// tool will read, not a claim about the library: the library bounds every table
/// it builds from the file, and this bound stops the tool reading a file it could
/// never represent.
constexpr std::size_t kMaxScenarioBytes = 32u * 1024u * 1024u;

void print_error(const cfm::Error& error) {
  std::cerr << "error: " << error.to_string() << "\n";
  for (const std::string& detail : error.details()) {
    std::cerr << "  detail: " << detail << "\n";
  }
}

#define CFM_TRY_OR_RETURN(name, expression, code)   \
  auto name##_parsed = (expression);                \
  if (!name##_parsed.has_value()) {                  \
    print_error(name##_parsed.error());              \
    return (code);                                   \
  }                                                  \
  auto& name = *name##_parsed

/// Trims ASCII whitespace from both ends without touching any other byte, so a
/// value that legitimately contains a non-ASCII space is preserved verbatim.
std::string_view trim(std::string_view text) {
  std::size_t begin = 0;
  std::size_t end = text.size();
  const auto is_space = [](char byte) {
    return byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n' || byte == '\f' || byte == '\v';
  };
  while (begin < end && is_space(text[begin])) {
    ++begin;
  }
  while (end > begin && is_space(text[end - 1])) {
    --end;
  }
  return text.substr(begin, end - begin);
}

std::vector<std::string> split_lines(std::string_view text) {
  std::vector<std::string> lines;
  std::size_t start = 0;
  while (true) {
    const std::size_t next = text.find('\n', start);
    if (next == std::string_view::npos) {
      lines.emplace_back(text.substr(start));
      break;
    }
    lines.emplace_back(text.substr(start, next - start));
    start = next + 1;
  }
  return lines;
}

// ===========================================================================
// Synthetic scenario
// ===========================================================================

/// One declared scope from a scenario file.
struct ScenarioScope {
  cfm::ScopeId id;
  cfm::ScopeKind kind = cfm::ScopeKind::Loop;
  std::string display_name;
  cfm::AuthoritySet bindings;
  cfm::ScopePolicy policy;
  std::vector<cfm::ScopeDependency> dependencies;
};

struct Scenario {
  cfm::DecisionClock clock{};
  cfm::DecisionPolicy policy;
  cfm::AuthoritySet bindings;
  cfm::AuthoritySet observed_bindings;
  bool authority_changed = false;
  std::vector<ScenarioScope> scopes;
  std::vector<cfm::Observation> observations;
  std::vector<cfm::CoolingFailure> failures;
  std::vector<cfm::DecisionInput::SolicitationRequest> solicitations;
  std::vector<cfm::DecisionInput::AttemptReport> attempt_reports;
  std::vector<std::pair<cfm::ScopeId, cfm::DecisionClock>> stable_since;
  std::vector<cfm::ScopeId> recovery_requests;
};

/// The section currently being read, so an assignment knows what it belongs to.
enum class Section {
  Global,
  Scope,
  Observation,
  Failure,
  Solicitation,
  AttemptReport,
  StableSince,
  RecoveryRequest,
};

class ScenarioReader {
 public:
  explicit ScenarioReader(std::string_view text) : text_(text) {}

  cfm::Result<Scenario> read() {
    Scenario scenario;
    Section section = Section::Global;
    ScenarioScope* scope = nullptr;
    cfm::Observation* observation = nullptr;
    cfm::CoolingFailure* failure = nullptr;
    cfm::DecisionInput::SolicitationRequest* solicitation = nullptr;
    cfm::DecisionInput::AttemptReport* report = nullptr;
    std::pair<cfm::ScopeId, cfm::DecisionClock> stable;
    bool has_stable = false;
    cfm::ScopeId recovery_scope;
    bool has_recovery = false;

    std::size_t line_number = 0;
    for (const std::string& raw : split_lines(text_)) {
      ++line_number;
      const std::string_view line = trim(raw);
      if (line.empty() || line[0] == '#') {
        continue;
      }
      if (line.front() == '[') {
        if (line.back() != ']') {
          return fail(line_number, "a section header must end with ']'");
        }
        if (observation != nullptr) {
          CFM_TRYV(finalize_observation(*observation));
          observation = nullptr;
        }
        const std::string_view name = trim(line.substr(1, line.size() - 2));
        if (name == "scope") {
          section = Section::Scope;
          scenario.scopes.emplace_back();
          scope = &scenario.scopes.back();
        } else if (name == "observation") {
          section = Section::Observation;
          scenario.observations.emplace_back();
          observation = &scenario.observations.back();
        } else if (name == "failure") {
          section = Section::Failure;
          scenario.failures.emplace_back();
          failure = &scenario.failures.back();
        } else if (name == "solicitation") {
          section = Section::Solicitation;
          scenario.solicitations.emplace_back();
          solicitation = &scenario.solicitations.back();
        } else if (name == "attempt-report") {
          section = Section::AttemptReport;
          scenario.attempt_reports.emplace_back();
          report = &scenario.attempt_reports.back();
        } else if (name == "stable-since") {
          section = Section::StableSince;
          stable = std::make_pair(cfm::ScopeId(), cfm::DecisionClock());
          has_stable = true;
        } else if (name == "recovery-request") {
          section = Section::RecoveryRequest;
          recovery_scope = cfm::ScopeId();
          has_recovery = true;
        } else {
          return fail(line_number, "unknown section name");
        }
        continue;
      }
      const std::size_t equals = line.find('=');
      if (equals == std::string_view::npos) {
        return fail(line_number, "expected 'key = value' or a '[section]' header");
      }
      const std::string key(trim(line.substr(0, equals)));
      const std::string value(trim(line.substr(equals + 1)));
      if (key.empty()) {
        return fail(line_number, "assignment has an empty key");
      }
      cfm::Result<void> applied = cfm::ok();
      switch (section) {
        case Section::Global:
          applied = apply_global(scenario, key, value, line_number);
          break;
        case Section::Scope:
          applied = scope != nullptr ? apply_scope(*scope, key, value, line_number)
                                     : fail(line_number, "no scope section is open");
          break;
        case Section::Observation:
          applied = observation != nullptr ? apply_observation(*observation, key, value, line_number)
                                           : fail(line_number, "no observation section is open");
          break;
        case Section::Failure:
          applied = failure != nullptr ? apply_failure(*failure, key, value, line_number)
                                       : fail(line_number, "no failure section is open");
          break;
        case Section::Solicitation:
          applied = solicitation != nullptr
                        ? apply_solicitation(*solicitation, key, value, line_number)
                        : fail(line_number, "no solicitation section is open");
          break;
        case Section::AttemptReport:
          applied = report != nullptr ? apply_report(*report, key, value, line_number)
                                      : fail(line_number, "no attempt-report section is open");
          break;
        case Section::StableSince:
          applied = has_stable ? apply_stable(stable, key, value, line_number)
                               : fail(line_number, "no stable-since section is open");
          break;
        case Section::RecoveryRequest:
          applied = has_recovery ? apply_recovery(recovery_scope, key, value, line_number)
                                 : fail(line_number, "no recovery-request section is open");
          break;
      }
      if (!applied.has_value()) {
        return applied.error();
      }
    }
    if (observation != nullptr) {
      CFM_TRYV(finalize_observation(*observation));
    }
    if (has_stable) {
      if (stable.first.empty() || !stable.second.present()) {
        return fail(line_number, "a stable-since section must name both a scope and a clock");
      }
      scenario.stable_since.push_back(stable);
    }
    if (has_recovery) {
      if (recovery_scope.empty()) {
        return fail(line_number, "a recovery-request section must name a scope");
      }
      scenario.recovery_requests.push_back(recovery_scope);
    }
    if (!scenario.clock.present()) {
      scenario.clock = cfm::DecisionClock(0);
    }
    CFM_TRYV(cfm::validate_policy(scenario.policy));
    CFM_TRYV(validate_scenario(scenario));
    return scenario;
  }

 private:
  static cfm::Error fail(std::size_t line, std::string message) {
    return cfm::Error(cfm::ErrorCode::MalformedRecord, std::move(message))
        .with_subject("line " + std::to_string(line));
  }

  static cfm::Result<void> validate_scenario(const Scenario& scenario) {
    for (const ScenarioScope& scope : scenario.scopes) {
      if (scope.id.empty()) {
        return cfm::Error(cfm::ErrorCode::MissingField, "a scope section must name an identity");
      }
    }
    for (const cfm::Observation& observation : scenario.observations) {
      if (observation.id.empty()) {
        return cfm::Error(cfm::ErrorCode::MissingField, "an observation must name an identity");
      }
      if (observation.scope.empty()) {
        return cfm::Error(cfm::ErrorCode::MissingField, "an observation must name a scope")
            .with_subject(observation.id.str());
      }
    }
    for (const cfm::CoolingFailure& failure : scenario.failures) {
      if (failure.id.empty()) {
        return cfm::Error(cfm::ErrorCode::MissingField, "a failure must name an identity");
      }
      if (failure.scope.empty()) {
        return cfm::Error(cfm::ErrorCode::MissingField, "a failure must name a scope")
            .with_subject(failure.id.str());
      }
    }
    return cfm::ok();
  }

  cfm::Result<void> apply_global(Scenario& scenario, const std::string& key, const std::string& value,
                                 std::size_t line) {
    if (key == "clock") {
      return assign_clock(scenario.clock, value, line);
    }
    if (key == "evidence-window") {
      return assign_duration(scenario.policy.evidence_window, value, line);
    }
    if (key == "confirm-min-observations") {
      return assign_u32(scenario.policy.confirm_min_observations, value, line);
    }
    if (key == "suspect-min-observations") {
      return assign_u32(scenario.policy.suspect_min_observations, value, line);
    }
    if (key == "healthy-min-observations") {
      return assign_u32(scenario.policy.healthy_min_observations, value, line);
    }
    if (key == "require-direct-witness") {
      return assign_bool(scenario.policy.require_direct_witness, value, line);
    }
    if (key == "safety-escalation-severity") {
      CFM_TRY(parsed, cfm::severity_from_token(value));
      scenario.policy.safety_escalation_severity = parsed;
      return cfm::ok();
    }
    if (key == "acknowledgement-window") {
      return assign_duration(scenario.policy.acknowledgement_window, value, line);
    }
    if (key == "authority-changed") {
      return assign_bool(scenario.authority_changed, value, line);
    }
    if (key == "binding" || key == "observed-binding") {
      cfm::AuthoritySet& set = key == "binding" ? scenario.bindings : scenario.observed_bindings;
      return assign_binding(set, value, line);
    }
    return fail(line, "unknown global key");
  }

  cfm::Result<void> apply_scope(ScenarioScope& scope, const std::string& key, const std::string& value,
                                std::size_t line) {
    if (key == "id") {
      CFM_TRY(parsed, cfm::ScopeId::parse(value));
      scope.id = parsed;
      return cfm::ok();
    }
    if (key == "kind") {
      CFM_TRY(parsed, cfm::scope_kind_from_token(value));
      scope.kind = parsed;
      return cfm::ok();
    }
    if (key == "name") {
      if (!cfm::is_valid_display_text(value, cfm::limits::kMaxDisplayNameBytes)) {
        return fail(line, "a display name must be printable text within the length bound");
      }
      scope.display_name = value;
      return cfm::ok();
    }
    if (key == "binding") {
      return assign_binding(scope.bindings, value, line);
    }
    if (key == "require") {
      return assign_requirement(scope.policy, value, line);
    }
    if (key == "strict-class") {
      CFM_TRY(parsed, cfm::failure_class_from_token(value));
      scope.policy.strict_classes.push_back(parsed);
      return cfm::ok();
    }
    if (key == "dwell") {
      return assign_duration(scope.policy.recovery_dwell, value, line);
    }
    if (key == "hysteresis") {
      return assign_duration(scope.policy.recovery_hysteresis, value, line);
    }
    if (key == "service-severity-floor") {
      CFM_TRY(parsed, cfm::severity_from_token(value));
      scope.policy.service_severity_floor = parsed;
      return cfm::ok();
    }
    if (key == "max-supply-temperature" || key == "min-thermal-margin" || key == "min-flow" ||
        key == "min-differential-pressure" || key == "declared-demand") {
      CFM_TRY(parsed, parse_declared(value, line));
      if (key == "max-supply-temperature") {
        scope.policy.envelope.max_supply_temperature = parsed;
      } else if (key == "min-thermal-margin") {
        scope.policy.envelope.min_thermal_margin = parsed;
      } else if (key == "min-flow") {
        scope.policy.envelope.min_flow = parsed;
      } else if (key == "min-differential-pressure") {
        scope.policy.envelope.min_differential_pressure = parsed;
      } else {
        scope.policy.envelope.declared_demand = parsed;
      }
      return cfm::ok();
    }
    if (key == "depends-on") {
      return assign_dependency(scope, value, line);
    }
    return fail(line, "unknown scope key");
  }

  cfm::Result<void> apply_observation(cfm::Observation& observation, const std::string& key,
                                      const std::string& value, std::size_t line) {
    if (key == "id") {
      CFM_TRY(parsed, cfm::ObservationId::parse(value));
      observation.id = parsed;
      return cfm::ok();
    }
    if (key == "scope") {
      CFM_TRY(parsed, cfm::ScopeId::parse(value));
      observation.scope = parsed;
      return cfm::ok();
    }
    if (key == "channel") {
      CFM_TRY(parsed, cfm::observation_channel_from_token(value));
      observation.channel = parsed;
      return cfm::ok();
    }
    if (key == "at") {
      return assign_clock(observation.observed_at, value, line);
    }
    if (key == "recorded-at") {
      return assign_clock(observation.recorded_at, value, line);
    }
    if (key == "producer") {
      observation.producer = value;
      return cfm::ok();
    }
    if (key == "sensor") {
      observation.sensor = value;
      return cfm::ok();
    }
    if (key == "sequence") {
      CFM_TRY(parsed, cfm::parse_uint64(value, UINT64_MAX));
      sequence_ = parsed;
      has_sequence_ = true;
      return cfm::ok();
    }
    if (key == "quality") {
      CFM_TRY(parsed, cfm::observation_quality_from_token(value));
      quality_ = parsed;
      has_quality_ = true;
      return cfm::ok();
    }
    if (key == "leak") {
      CFM_TRY(parsed, cfm::leak_state_from_token(value));
      observation.leak = parsed;
      return cfm::ok();
    }
    if (key == "carried-forward") {
      return assign_bool(observation.carried_forward, value, line);
    }
    if (key == "evidence-generation") {
      CFM_TRY(parsed, cfm::parse_uint64(value, UINT64_MAX));
      observation.evidence_generation = cfm::EvidenceGeneration(parsed);
      return cfm::ok();
    }
    if (key == "value") {
      CFM_TRY(parsed, cfm::parse_int64(value, INT64_MIN, INT64_MAX));
      pending_value_ = parsed;
      has_value_ = true;
      return cfm::ok();
    }
    if (key == "unit") {
      pending_unit_ = value;
      return cfm::ok();
    }
    if (key == "indeterminate") {
      bool flag = false;
      CFM_TRYV(assign_bool(flag, value, line));
      if (flag) {
        observation.quantity = cfm::Quantity::indeterminate();
        has_value_ = false;
      }
      return cfm::ok();
    }
    return fail(line, "unknown observation key");
  }

  cfm::Result<void> apply_failure(cfm::CoolingFailure& failure, const std::string& key,
                                  const std::string& value, std::size_t line) {
    if (key == "id") {
      CFM_TRY(parsed, cfm::FailureId::parse(value));
      failure.id = parsed;
      return cfm::ok();
    }
    if (key == "scope") {
      CFM_TRY(parsed, cfm::ScopeId::parse(value));
      failure.scope = parsed;
      return cfm::ok();
    }
    if (key == "class") {
      CFM_TRY(parsed, cfm::failure_class_from_token(value));
      failure.failure_class = parsed;
      return cfm::ok();
    }
    if (key == "confirmation") {
      CFM_TRY(parsed, cfm::confirmation_state_from_token(value));
      failure.confirmation = parsed;
      return cfm::ok();
    }
    if (key == "severity") {
      CFM_TRY(parsed, cfm::severity_from_token(value));
      failure.severity = parsed;
      return cfm::ok();
    }
    if (key == "urgency") {
      CFM_TRY(parsed, cfm::urgency_from_token(value));
      failure.urgency = parsed;
      return cfm::ok();
    }
    if (key == "time-to-impact") {
      CFM_TRY(parsed, cfm::time_to_impact_from_token(value));
      failure.time_to_impact = parsed;
      return cfm::ok();
    }
    if (key == "at") {
      return assign_clock(failure.confirmed_at, value, line);
    }
    if (key == "basis") {
      CFM_TRY(parsed, cfm::ObservationId::parse(value));
      failure.basis.push_back(parsed);
      return cfm::ok();
    }
    if (key == "shared-source") {
      CFM_TRY(parsed, cfm::ScopeId::parse(value));
      failure.shared_source = parsed;
      return cfm::ok();
    }
    if (key == "rationale") {
      if (!cfm::is_valid_display_text(value, cfm::limits::kMaxTextBytes)) {
        return fail(line, "a rationale must be printable text within the length bound");
      }
      failure.rationale = value;
      return cfm::ok();
    }
    return fail(line, "unknown failure key");
  }

  cfm::Result<void> apply_solicitation(cfm::DecisionInput::SolicitationRequest& solicitation,
                                       const std::string& key, const std::string& value,
                                       std::size_t line) {
    if (key == "scope") {
      CFM_TRY(parsed, cfm::ScopeId::parse(value));
      solicitation.scope = parsed;
      return cfm::ok();
    }
    if (key == "mutation") {
      CFM_TRY(parsed, cfm::MutationId::parse(value));
      solicitation.solicitation = parsed;
      return cfm::ok();
    }
    if (key == "attempt") {
      CFM_TRY(parsed, cfm::parse_uint64(value, UINT32_MAX));
      CFM_TRY(ordinal, cfm::AttemptOrdinal::parse(static_cast<std::uint32_t>(parsed)));
      solicitation.attempt = ordinal;
      return cfm::ok();
    }
    if (key == "action") {
      CFM_TRY(parsed, cfm::response_action_from_token(value));
      solicitation.action = parsed;
      return cfm::ok();
    }
    if (key == "addressee") {
      solicitation.addressee = value;
      return cfm::ok();
    }
    return fail(line, "unknown solicitation key");
  }

  cfm::Result<void> apply_report(cfm::DecisionInput::AttemptReport& report, const std::string& key,
                                 const std::string& value, std::size_t line) {
    if (key == "attempt") {
      CFM_TRY(parsed, cfm::AttemptId::parse(value));
      report.attempt = parsed;
      return cfm::ok();
    }
    if (key == "state") {
      CFM_TRY(parsed, cfm::attempt_state_from_token(value));
      report.state = parsed;
      return cfm::ok();
    }
    if (key == "at") {
      return assign_clock(report.at, value, line);
    }
    if (key == "effect-observation") {
      CFM_TRY(parsed, cfm::ObservationId::parse(value));
      report.effect_observation = parsed;
      return cfm::ok();
    }
    if (key == "verdict") {
      if (!cfm::is_valid_display_text(value, cfm::limits::kMaxWitnessBytes)) {
        return fail(line, "a verdict must be printable text within the length bound");
      }
      report.verdict = value;
      return cfm::ok();
    }
    return fail(line, "unknown attempt-report key");
  }

  static cfm::Result<void> apply_stable(std::pair<cfm::ScopeId, cfm::DecisionClock>& entry,
                                        const std::string& key, const std::string& value,
                                        std::size_t line) {
    if (key == "scope") {
      CFM_TRY(parsed, cfm::ScopeId::parse(value));
      entry.first = parsed;
      return cfm::ok();
    }
    if (key == "since") {
      return assign_clock(entry.second, value, line);
    }
    return fail(line, "unknown stable-since key");
  }

  static cfm::Result<void> apply_recovery(cfm::ScopeId& scope, const std::string& key,
                                          const std::string& value, std::size_t line) {
    if (key == "scope") {
      CFM_TRY(parsed, cfm::ScopeId::parse(value));
      scope = parsed;
      return cfm::ok();
    }
    return fail(line, "unknown recovery-request key");
  }

  static cfm::Result<void> assign_clock(cfm::DecisionClock& target, const std::string& value,
                                        std::size_t line) {
    CFM_TRY(parsed, cfm::parse_int64(value, -1, cfm::limits::kMaxTimestampMilliseconds));
    if (parsed < 0) {
      return fail(line, "a clock is never negative");
    }
    CFM_TRY(clock, cfm::DecisionClock::parse(parsed));
    target = clock;
    return cfm::ok();
  }

  static cfm::Result<void> assign_duration(cfm::DurationMilliseconds& target, const std::string& value,
                                           std::size_t line) {
    CFM_TRY(parsed, cfm::parse_int64(value, 0, cfm::limits::kMaxWindowMilliseconds));
    CFM_TRY(duration, cfm::DurationMilliseconds::parse(parsed));
    (void)line;
    target = duration;
    return cfm::ok();
  }

  static cfm::Result<void> assign_u32(std::uint32_t& target, const std::string& value,
                                      std::size_t line) {
    CFM_TRY(parsed, cfm::parse_uint64(value, UINT32_MAX));
    (void)line;
    target = static_cast<std::uint32_t>(parsed);
    return cfm::ok();
  }

  static cfm::Result<void> assign_bool(bool& target, const std::string& value, std::size_t line) {
    if (value == "true" || value == "1" || value == "yes") {
      target = true;
      return cfm::ok();
    }
    if (value == "false" || value == "0" || value == "no") {
      target = false;
      return cfm::ok();
    }
    return fail(line, "expected a boolean (true/false)");
  }

  /// A declared quantity is written "value:unit", for example "1800000:mL/s".
  static cfm::Result<cfm::DeclaredQuantity> parse_declared(const std::string& value,
                                                           std::size_t line) {
    const std::size_t colon = value.rfind(':');
    if (colon == std::string::npos) {
      return fail(line, "a declared quantity is written value:unit");
    }
    CFM_TRY(parsed_value, cfm::parse_int64(value.substr(0, colon), INT64_MIN, INT64_MAX));
    return cfm::DeclaredQuantity::make(parsed_value, value.substr(colon + 1));
  }

  /// A binding is written "role=owner:identity:generation".
  static cfm::Result<void> assign_binding(cfm::AuthoritySet& set, const std::string& value,
                                          std::size_t line) {
    const std::size_t equals = value.find('=');
    if (equals == std::string::npos) {
      return fail(line, "a binding is written role=owner:identity:generation");
    }
    const std::string role = value.substr(0, equals);
    const std::string rest = value.substr(equals + 1);
    const std::size_t first_colon = rest.find(':');
    const std::size_t last_colon = rest.rfind(':');
    if (first_colon == std::string::npos || first_colon == last_colon) {
      return fail(line, "a binding is written role=owner:identity:generation");
    }
    CFM_TRY(generation, cfm::parse_uint64(rest.substr(last_colon + 1), UINT64_MAX));
    CFM_TRY(reference, cfm::AuthorityRef::make(
                           rest.substr(0, first_colon),
                           rest.substr(first_colon + 1, last_colon - first_colon - 1),
                           cfm::ExternalGeneration(generation)));
    return set.set(role, reference);
  }

  /// An evidence requirement is written "channel:window".
  static cfm::Result<void> assign_requirement(cfm::ScopePolicy& policy, const std::string& value,
                                              std::size_t line) {
    const std::size_t colon = value.rfind(':');
    if (colon == std::string::npos) {
      return fail(line, "an evidence requirement is written channel:window");
    }
    CFM_TRY(channel, cfm::observation_channel_from_token(value.substr(0, colon)));
    CFM_TRY(parsed, cfm::parse_int64(value.substr(colon + 1), 0, cfm::limits::kMaxWindowMilliseconds));
    CFM_TRY(window, cfm::DurationMilliseconds::parse(parsed));
    policy.requirements.push_back(cfm::EvidenceRequirement{channel, window});
    return cfm::ok();
  }

  /// A dependency is written "upstream:kind:share-ppm".
  static cfm::Result<void> assign_dependency(ScenarioScope& scope, const std::string& value,
                                             std::size_t line) {
    const std::size_t first = value.find(':');
    const std::size_t last = value.rfind(':');
    if (first == std::string::npos || first == last) {
      return fail(line, "a dependency is written upstream:kind:share-ppm");
    }
    CFM_TRY(upstream, cfm::ScopeId::parse(value.substr(0, first)));
    CFM_TRY(kind, cfm::dependency_kind_from_token(value.substr(first + 1, last - first - 1)));
    CFM_TRY(share, cfm::parse_int64(value.substr(last + 1), 0, 1000000));
    cfm::ScopeDependency dependency;
    dependency.upstream = upstream;
    dependency.kind = kind;
    dependency.share_parts_per_million = share;
    scope.dependencies.push_back(dependency);
    return cfm::ok();
  }

  /// Finalises the quantity of the observation currently being read, once its
  /// value, unit, quality and sequence are all known.
  cfm::Result<void> finalize_observation(cfm::Observation& observation) {
    const bool status_channel = cfm::channel_unit(observation.channel).empty();
    // A reading on a channel that carries a unit must carry that unit. Refusing
    // here is the difference between "the scenario is wrong" and "the channel has
    // no evidence", and only the first is true.
    if (has_value_ && !status_channel && pending_unit_.empty()) {
      return cfm::Error(cfm::ErrorCode::MissingField,
                        "a scalar reading must carry the unit of its channel")
          .with_subject(observation.id.empty() ? std::string("observation") : observation.id.str())
          .with_detail("channel " + std::string(cfm::to_token(observation.channel)));
    }
    if (has_value_) {
      CFM_TRY(quantity, cfm::Quantity::observed(pending_value_, pending_unit_,
                                                has_quality_ ? quality_ : cfm::ObservationQuality::Good,
                                                cfm::ObservationSequence(has_sequence_ ? sequence_ : 0)));
      observation.quantity = quantity;
    } else if (!status_channel) {
      observation.quantity = cfm::Quantity::indeterminate();
    } else {
      observation.quantity = cfm::Quantity::indeterminate();
    }
    if (has_sequence_ && !observation.quantity.has_value()) {
      // A sequence without a reading is a producer that reported nothing on a
      // numbered sample; the observation keeps the sequence through its own
      // evidence generation instead, so nothing is invented here.
      observation.evidence_generation =
          cfm::EvidenceGeneration(static_cast<std::uint64_t>(sequence_));
    }
    has_value_ = false;
    has_quality_ = false;
    has_sequence_ = false;
    pending_unit_.clear();
    return cfm::ok();
  }

  std::string_view text_;
  bool has_value_ = false;
  std::int64_t pending_value_ = 0;
  std::string pending_unit_;
  bool has_quality_ = false;
  cfm::ObservationQuality quality_ = cfm::ObservationQuality::Good;
  bool has_sequence_ = false;
  std::uint64_t sequence_ = 0;
};

}  // namespace

// ===========================================================================
// Command line
// ===========================================================================

namespace {

struct Options {
  std::string command;
  std::string scenario_path;
  std::string store_path;
  std::string scope;
  std::string mutation;
  std::uint32_t attempt = 0;
  bool has_attempt = false;
  bool scenario_only = false;
  bool explain = false;
  bool publish = false;
  bool verify = false;
  bool canonical = false;
};

cfm::Result<Options> parse_options(const std::vector<std::string>& arguments) {
  Options options;
  if (arguments.empty()) {
    return cfm::Error(cfm::ErrorCode::InvalidArgument, "a command is required");
  }
  options.command = arguments[0];
  for (std::size_t index = 1; index < arguments.size(); ++index) {
    const std::string& argument = arguments[index];
    auto value_of = [&](std::string_view prefix) -> std::optional<std::string> {
      if (argument.rfind(prefix, 0) == 0) {
        return argument.substr(prefix.size());
      }
      return std::nullopt;
    };
    if (argument == "--scenario-only") {
      options.scenario_only = true;
    } else if (argument == "--explain") {
      options.explain = true;
    } else if (argument == "--publish") {
      options.publish = true;
    } else if (argument == "--verify") {
      options.verify = true;
    } else if (argument == "--canonical") {
      options.canonical = true;
    } else if (const auto option_0 = value_of("--scenario=")) {
      options.scenario_path = *option_0;
    } else if (const auto option_1 = value_of("--store=")) {
      options.store_path = *option_1;
    } else if (const auto option_2 = value_of("--scope=")) {
      options.scope = *option_2;
    } else if (const auto option_3 = value_of("--mutation=")) {
      options.mutation = *option_3;
    } else if (const auto option_4 = value_of("--attempt=")) {
      CFM_TRY(parsed, cfm::parse_uint64(*option_4, UINT32_MAX));
      if (parsed == 0) {
        return cfm::Error(cfm::ErrorCode::InvalidArgument,
                          "an attempt ordinal is 1-based and must not be zero");
      }
      options.attempt = static_cast<std::uint32_t>(parsed);
      options.has_attempt = true;
    } else {
      return cfm::Error(cfm::ErrorCode::InvalidArgument, "unknown option")
          .with_subject(argument);
    }
  }
  return options;
}

/// Reads a whole file through the narrowest possible interface: this tool is an
/// operator tool, not a sandbox, so it reads exactly the path it was given and
/// refuses anything larger than the documented bound.
cfm::Result<std::string> read_text_file(const std::string& path, std::size_t max_bytes) {
  std::FILE* file = nullptr;
#if defined(_WIN32)
  if (fopen_s(&file, path.c_str(), "rb") != 0) {
    file = nullptr;
  }
#else
  file = std::fopen(path.c_str(), "rb");
#endif
  if (file == nullptr) {
    return cfm::Error(cfm::ErrorCode::StoreNotFound, "the file could not be opened")
        .with_subject(path);
  }
  std::string content;
  char buffer[8192];
  while (true) {
    const std::size_t read = std::fread(buffer, 1, sizeof(buffer), file);
    if (read > 0) {
      if (content.size() + read > max_bytes) {
        std::fclose(file);
        return cfm::Error(cfm::ErrorCode::LimitExceeded, "the file exceeds the accepted size bound")
            .with_subject(path);
      }
      content.append(buffer, read);
    }
    if (read < sizeof(buffer)) {
      if (std::ferror(file) != 0) {
        std::fclose(file);
        return cfm::Error(cfm::ErrorCode::IoError, "the file could not be read").with_subject(path);
      }
      break;
    }
  }
  std::fclose(file);
  return content;
}

void print_verification(const cfm::VerifyReport& report) {
  std::cout << "store " << report.store_id.str() << "\n"
            << "head generation      " << report.head.value() << "\n"
            << "head digest          " << report.head_digest.to_hex() << "\n"
            << "head verified        " << (report.head_verified ? "yes" : "no") << "\n"
            << "manifest verified    " << (report.manifest_verified ? "yes" : "no") << "\n"
            << "floor verified       " << (report.floor_verified ? "yes" : "no") << "\n"
            << "chain verified       " << (report.chain_verified ? "yes" : "no") << "\n"
            << "canonical fixed point " << (report.canonical_fixed_point_verified ? "yes" : "no") << "\n"
            << "recovered state      " << (report.recovered_state ? "yes" : "no") << "\n"
            << "publication allowed  " << (report.publication_allowed ? "yes" : "no") << "\n"
            << "generations present  " << report.generations_present << "\n"
            << "generations verified " << report.generations_verified << "\n"
            << "staged residue       " << report.staged_residue_found << "\n"
            << "orphan generations   " << report.orphan_generations_found << "\n"
            << "unreferenced         " << report.unreferenced_generations_found << "\n"
            << "quarantined          " << report.quarantined_found << "\n"
            << "unresolved attempts  " << report.unresolved_attempts_found << "\n";
  for (const cfm::VerifyFinding& finding : report.findings) {
    std::cout << "finding " << cfm::to_token(finding.severity) << " " << finding.code;
    if (!finding.subject.empty()) {
      std::cout << " subject=" << finding.subject;
    }
    if (!finding.detail.empty()) {
      std::cout << " detail=" << finding.detail;
    }
    std::cout << "\n";
  }
  std::cout << (report.ok() ? "verify ok\n" : "verify FAILED\n");
}

void print_state_brief(const cfm::CoolingFailureState& state) {
  std::cout << "generation " << state.generation.value() << " parent " << state.parent_generation.value()
            << " clock " << state.evaluated_at.milliseconds() << "\n";
  std::cout << "scopes " << state.scopes.size() << " failures " << state.failures.size() << " plans "
            << state.plans.size() << " evidence " << state.evidence.size() << " decisions "
            << state.decisions.size() << "\n";
  for (const cfm::ScopeDecision& decision : state.decisions) {
    std::cout << "-- scope " << decision.scope.str() << " severity " << cfm::to_token(decision.severity)
              << " urgency " << cfm::to_token(decision.urgency) << " plan "
              << cfm::to_token(decision.plan_lifecycle) << " recovery "
              << cfm::to_token(decision.recovery) << " binding " << cfm::to_token(decision.binding_status)
              << "\n";
    for (const cfm::FailureClass failure_class : decision.confirmed_classes) {
      std::cout << "   confirmed " << cfm::to_token(failure_class) << "\n";
    }
    for (const cfm::FailureClass failure_class : decision.suspected_classes) {
      std::cout << "   suspected " << cfm::to_token(failure_class) << "\n";
    }
    for (const cfm::FailureClass failure_class : decision.unknown_classes) {
      std::cout << "   unknown   " << cfm::to_token(failure_class) << "\n";
    }
    for (const cfm::ObservationChannel channel : decision.evidence_gaps) {
      std::cout << "   gap       " << cfm::to_token(channel) << "\n";
    }
    for (const std::string& line : decision.explanation) {
      std::cout << "   " << line << "\n";
    }
  }
  for (const cfm::AttemptId& attempt : state.unresolved_attempts) {
    std::cout << "unresolved attempt " << attempt.str() << "\n";
  }
}

int run_version() {
  std::cout << "cfmctl " << cfm::version_string() << "\n"
            << "component " << cfm::component_id() << "\n"
            << "boundary  " << cfm::systems_boundary() << "\n"
            << "canonical format " << cfm::canonical_format_name() << " v"
            << cfm::canonical_format_version() << "\n";
  return kExitOk;
}

int run_evaluate(const Options& options) {
  if (options.scenario_path.empty()) {
    std::cerr << "error: evaluate needs --scenario=<file>\n";
    return kExitUsage;
  }
  const cfm::Result<std::string> text = read_text_file(options.scenario_path, kMaxScenarioBytes);
  if (!text.has_value()) {
    print_error(text.error());
    return kExitInput;
  }
  const cfm::Result<Scenario> scenario = ScenarioReader(*text).read();
  if (!scenario.has_value()) {
    print_error(scenario.error());
    return kExitInput;
  }

  cfm::CoolingFailureState skeleton;
  skeleton.evaluated_at = scenario->clock;
  skeleton.bindings = scenario->bindings;
  for (const ScenarioScope& declared : scenario->scopes) {
    cfm::CoolingScope scope;
    scope.id = declared.id;
    scope.kind = declared.kind;
    scope.display_name = declared.display_name;
    scope.bindings = declared.bindings;
    scope.policy = declared.policy;
    scope.dependencies = declared.dependencies;
    skeleton.scopes.push_back(std::move(scope));
  }
  skeleton.failures = scenario->failures;

  cfm::ObservationSet observations;
  for (const cfm::Observation& observation : scenario->observations) {
    const cfm::Result<void> added = observations.add(observation);
    if (!added.has_value()) {
      print_error(added.error());
      return kExitInput;
    }
  }
  observations.sort_canonical();

  if (options.scenario_only) {
    const cfm::Result<void> valid = cfm::validate_policy(scenario->policy);
    if (!valid.has_value()) {
      print_error(valid.error());
      return kExitNegative;
    }
    std::cout << "scenario " << options.scenario_path << " ok\n"
              << "scopes " << skeleton.scopes.size() << " observations " << observations.size()
              << " failures " << skeleton.failures.size() << " solicitations "
              << scenario->solicitations.size() << "\n";
    return kExitOk;
  }

  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = scenario->policy;
  input.clock = scenario->clock;
  input.bindings = scenario->bindings;
  input.observed_bindings.current = scenario->observed_bindings;
  input.authority_changed = scenario->authority_changed;
  input.solicitations = scenario->solicitations;
  input.attempt_reports = scenario->attempt_reports;
  input.stable_since = scenario->stable_since;
  input.recovery_requests = scenario->recovery_requests;

  cfm::Result<cfm::DecisionOutcome> outcome = cfm::evaluate(input);
  if (!outcome.has_value()) {
    print_error(outcome.error());
    return kExitNegative;
  }

  if (options.canonical) {
    std::cout << cfm::encode_state(outcome->state);
  } else {
    print_state_brief(outcome->state);
    if (options.explain) {
      std::cout << "-- explanation\n";
      for (const std::string& line : outcome->explanation) {
        std::cout << line << "\n";
      }
    }
  }

  if (!options.publish) {
    return kExitOk;
  }
  if (options.store_path.empty() || options.mutation.empty() || !options.has_attempt) {
    std::cerr << "error: --publish needs --store=<dir> --mutation=<id> --attempt=<n>\n";
    return kExitUsage;
  }
  cfm::StoreOptions store_options;
  store_options.root = options.store_path;
  cfm::Result<cfm::Store> store = cfm::Store::open(store_options);
  if (!store.has_value()) {
    print_error(store.error());
    return kExitNegative;
  }
  cfm::PublicationRequest request;
  request.authority = scenario->bindings;
  request.epoch = store->epoch();
  request.incarnation = store->incarnation();
  CFM_TRY_OR_RETURN(mutation, cfm::MutationId::parse(options.mutation), kExitUsage);
  request.mutation = mutation;
  CFM_TRY_OR_RETURN(ordinal, cfm::AttemptOrdinal::parse(options.attempt), kExitUsage);
  request.attempt = ordinal;
  request.body = outcome->state;
  cfm::Result<cfm::PublicationReceipt> receipt = store->publish(request);
  if (!receipt.has_value()) {
    print_error(receipt.error());
    return kExitNegative;
  }
  std::cout << "published generation " << receipt->generation.value() << " digest "
            << receipt->digest.to_hex() << " durability " << cfm::to_token(receipt->durability)
            << (receipt->replayed ? " replayed" : "") << "\n";
  return kExitOk;
}

int run_inspect(const Options& options) {
  if (options.store_path.empty()) {
    std::cerr << "error: inspect needs --store=<dir>\n";
    return kExitUsage;
  }
  cfm::StoreOptions store_options;
  store_options.root = options.store_path;
  store_options.mode = cfm::StoreMode::ReadOnly;
  cfm::Result<cfm::Store> store = cfm::Store::open(store_options);
  if (!store.has_value()) {
    print_error(store.error());
    return kExitNegative;
  }
  if (options.verify) {
    cfm::Result<cfm::VerifyReport> report = store->verify(cfm::VerifyOptions{});
    if (!report.has_value()) {
      print_error(report.error());
      return kExitNegative;
    }
    print_verification(report.value());
    return report->ok() ? kExitOk : kExitNegative;
  }
  cfm::Result<cfm::StoreInfo> info = store->info();
  if (!info.has_value()) {
    print_error(info.error());
    return kExitNegative;
  }
  std::cout << "store " << info->store_id.str() << " root " << info->root << "\n"
            << "head " << info->head.value() << " digest " << info->head_digest.to_hex() << "\n"
            << "floor " << info->floor.value() << " commit " << info->commit_sequence.value() << "\n"
            << "mode " << cfm::to_token(info->mode) << " open-state " << cfm::to_token(info->open_state)
            << "\n"
            << "retained generations " << info->retained_generations << " idempotency records "
            << info->idempotency_records << "\n"
            << "publication allowed " << (info->publication_allowed ? "yes" : "no") << "\n";
  cfm::Result<std::vector<cfm::HistoryEntry>> history = store->history();
  if (history.has_value()) {
    for (const cfm::HistoryEntry& entry : history.value()) {
      std::cout << "generation " << entry.generation.value() << " digest " << entry.digest.to_hex()
                << " parent " << entry.parent_generation.value() << " bytes " << entry.file_bytes
                << (entry.is_head ? " head" : "") << (entry.chain_verified ? " verified" : "") << "\n";
    }
  }
  cfm::Result<cfm::CoolingFailureState> head = store->head();
  if (head.has_value()) {
    print_state_brief(head.value());
  } else {
    std::cout << "head state unavailable: " << head.error().to_string() << "\n";
  }
  return kExitOk;
}

int run_explain(const Options& options) {
  if (options.store_path.empty()) {
    std::cerr << "error: explain needs --store=<dir>\n";
    return kExitUsage;
  }
  cfm::StoreOptions store_options;
  store_options.root = options.store_path;
  store_options.mode = cfm::StoreMode::ReadOnly;
  cfm::Result<cfm::Store> store = cfm::Store::open(store_options);
  if (!store.has_value()) {
    print_error(store.error());
    return kExitNegative;
  }
  cfm::Result<cfm::CoolingFailureState> head = store->head();
  if (!head.has_value()) {
    print_error(head.error());
    return kExitNegative;
  }
  if (!options.scope.empty()) {
    CFM_TRY_OR_RETURN(scope_id, cfm::ScopeId::parse(options.scope), kExitUsage);
    const cfm::ScopeDecision* decision = cfm::find_decision(head.value(), scope_id);
    if (decision == nullptr) {
      std::cerr << "error: no decision is published for that scope\n";
      return kExitNegative;
    }
    for (const std::string& line : decision->explanation) {
      std::cout << line << "\n";
    }
    return kExitOk;
  }
  for (const cfm::ScopeDecision& decision : head->decisions) {
    for (const std::string& line : decision.explanation) {
      std::cout << line << "\n";
    }
  }
  return kExitOk;
}

int run_recover(const Options& options) {
  if (options.store_path.empty()) {
    std::cerr << "error: recover needs --store=<dir>\n";
    return kExitUsage;
  }
  cfm::StoreOptions store_options;
  store_options.root = options.store_path;
  cfm::Result<cfm::Store> store = cfm::Store::open(store_options);
  if (!store.has_value()) {
    print_error(store.error());
    return kExitNegative;
  }
  cfm::Result<cfm::RecoveryReport> report = store->recover(cfm::RecoveryOptions{});
  if (!report.has_value()) {
    print_error(report.error());
    return kExitNegative;
  }
  std::cout << "recovery outcome " << cfm::to_token(report->outcome) << " head "
            << report->head_before.value() << " -> " << report->head_after.value() << " digest "
            << report->head_digest_after.to_hex() << " residue removed " << report->residue_removed
            << (report->floor_respected ? " floor-respected" : " FLOOR-VIOLATION") << "\n";
  for (const std::string& step : report->steps) {
    std::cout << "step " << step << "\n";
  }
  if (!report->explanation.empty()) {
    std::cout << report->explanation << "\n";
  }
  return kExitOk;
}

int run_reconcile(const Options& options) {
  if (options.store_path.empty() || options.mutation.empty() || !options.has_attempt) {
    std::cerr << "error: reconcile needs --store=<dir> --mutation=<id> --attempt=<n>\n";
    return kExitUsage;
  }
  cfm::StoreOptions store_options;
  store_options.root = options.store_path;
  cfm::Result<cfm::Store> store = cfm::Store::open(store_options);
  if (!store.has_value()) {
    print_error(store.error());
    return kExitNegative;
  }
  CFM_TRY_OR_RETURN(mutation, cfm::MutationId::parse(options.mutation), kExitUsage);
  CFM_TRY_OR_RETURN(ordinal, cfm::AttemptOrdinal::parse(options.attempt), kExitUsage);
  cfm::Result<std::size_t> reconciled = store->reconcile_unresolved(cfm::AuthoritySet{}, mutation, ordinal);
  if (!reconciled.has_value()) {
    print_error(reconciled.error());
    return kExitNegative;
  }
  std::cout << "reconciled attempts " << *reconciled << "\n";
  return kExitOk;
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string> arguments;
  arguments.reserve(static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
  for (int index = 1; index < argc; ++index) {
    arguments.emplace_back(argv[index]);
  }
  if (arguments.empty() || arguments[0] == "--help" || arguments[0] == "-h" ||
      arguments[0] == "help") {
    std::cout << "cfmctl " << cfm::version_string() << " - " << cfm::systems_boundary() << "\n"
              << "\n"
              << "usage: cfmctl <command> [options]\n"
              << "\n"
              << "  version\n"
              << "  evaluate  --scenario=<file> [--scenario-only] [--canonical] [--explain]\n"
              << "            [--publish --store=<dir> --mutation=<id> --attempt=<n>]\n"
              << "  inspect   --store=<dir> [--verify]\n"
              << "  explain   --store=<dir> [--scope=<id>]\n"
              << "  recover   --store=<dir>\n"
              << "  reconcile --store=<dir> --mutation=<id> --attempt=<n>\n"
              << "\n"
              << "cfmctl never actuates cooling equipment. Every response it reports is a bounded\n"
              << "request recorded against a decision, and every response it publishes is a\n"
              << "generation of this component's own durable state.\n";
    return arguments.empty() ? kExitUsage : kExitOk;
  }

  const cfm::Result<Options> options = parse_options(arguments);
  if (!options.has_value()) {
    print_error(options.error());
    return kExitUsage;
  }
  try {
    if (options->command == "version") {
      return run_version();
    }
    if (options->command == "evaluate") {
      return run_evaluate(options.value());
    }
    if (options->command == "inspect") {
      return run_inspect(options.value());
    }
    if (options->command == "explain") {
      return run_explain(options.value());
    }
    if (options->command == "recover") {
      return run_recover(options.value());
    }
    if (options->command == "reconcile") {
      return run_reconcile(options.value());
    }
    std::cerr << "error: unknown command " << options->command << "\n";
    return kExitUsage;
  } catch (const std::exception& error) {
    // A Result dereference on a failed value throws std::logic_error. That is a
    // defect in this tool, and it is reported as such rather than as a refusal.
    std::cerr << "error: internal failure: " << error.what() << "\n";
    return kExitNegative;
  }
}
