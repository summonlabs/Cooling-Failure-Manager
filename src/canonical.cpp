// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Canonical text encoding of cooling-failure state.
//
// The encoding has one job: turn a state into the single byte string that
// represents it, so that two states which differ only in insertion order, in
// container iteration order or in which process built them encode identically,
// and so that any corruption of the bytes is detectable rather than plausible.
//
// The rules, all of them enforced by the decoder:
//   * the first line names the format and its version, so an incompatible file is
//     refused instead of misread;
//   * records are emitted in a fixed order and, within a group, in the canonical
//     order established by canonicalize();
//   * every free-text field is escaped, so a record can never contain the record
//     separator;
//   * every number is canonical decimal and every enumeration is its stable token,
//     so an unknown token is refused rather than defaulted;
//   * the last line carries the record count and a digest over every preceding
//     byte, so truncation, duplication and reordering are all detected.

#include "dccp/cooling_failure_manager/canonical.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "dccp/cooling_failure_manager/classify.hpp"
#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/text.hpp"

namespace dccp::cooling_failure_manager {
namespace {

constexpr char kSeparator = '\t';
constexpr std::string_view kFormatName = "dccp-cooling-failure-state";
constexpr std::uint32_t kFormatVersion = 1;
constexpr std::string_view kHeaderRecord = "dccp-cooling-failure-state";
constexpr std::string_view kEndRecord = "end";

/// Appends a canonical decimal integer.
void append_number(std::string& out, std::int64_t value) { out += to_decimal(value); }
void append_number(std::string& out, std::uint64_t value) { out += to_decimal(value); }

/// Appends an escaped text field.
void append_text(std::string& out, std::string_view value) { out += escape_text(value); }

/// Appends a canonical boolean.
void append_bool(std::string& out, bool value) { out += value ? "1" : "0"; }

/// Appends a clock. An absent clock is written as an empty field: a negative
/// clock is not a canonical value, so the format has exactly one spelling of
/// "this was never set" and the decoder accepts exactly that spelling.
void append_clock(std::string& out, DecisionClock clock) {
  if (clock.present()) {
    append_number(out, clock.milliseconds());
  }
}

/// Appends one enumeration token.
template <class Enum>
void append_token(std::string& out, Enum value) {
  out += to_token(value);
}

/// The record collector keeps the record count and the running body so the
/// trailing digest covers exactly the bytes the decoder will re-read.
class RecordWriter {
 public:
  void header(std::string_view line) {
    body_ += line;
    body_ += '\n';
  }

  void record(std::string line) {
    body_ += line;
    body_ += '\n';
    ++count_;
  }

  std::string finish() const {
    std::string out = body_;
    out += kEndRecord;
    out += kSeparator;
    out += to_decimal(count_);
    out += kSeparator;
    out += digest_bytes(body_).to_hex();
    out += '\n';
    return out;
  }

  std::size_t count() const noexcept { return count_; }

 private:
  std::string body_;
  std::size_t count_ = 0;
};

}  // namespace

std::string_view canonical_format_name() noexcept { return kFormatName; }

std::uint32_t canonical_format_version() noexcept { return kFormatVersion; }

Digest attempt_record_digest(std::string_view canonical_record) {
  return digest_bytes(canonical_record);
}

std::string encode_state(const CoolingFailureState& state) {
  RecordWriter writer;

  // The header names the format, its version, and the two generation numbers the
  // state carries. It is not counted as a record.
  {
    std::string line(kHeaderRecord);
    line += kSeparator;
    line += to_decimal(static_cast<std::uint64_t>(kFormatVersion));
    line += kSeparator;
    line += "generation=";
    append_number(line, state.generation.value());
    line += kSeparator;
    line += "parent=";
    append_number(line, state.parent_generation.value());
    line += kSeparator;
    line += "clock=";
    append_clock(line, state.evaluated_at);
    writer.header(line);
  }

  // The counts record, so a reader can check the body it read against what the
  // encoder said it would write.
  {
    std::string line("state");
    line += kSeparator;
    line += "bindings=" + to_decimal(static_cast<std::uint64_t>(state.bindings.entries().size()));
    line += kSeparator;
    line += "scopes=" + to_decimal(static_cast<std::uint64_t>(state.scopes.size()));
    line += kSeparator;
    line += "failures=" + to_decimal(static_cast<std::uint64_t>(state.failures.size()));
    line += kSeparator;
    line += "plans=" + to_decimal(static_cast<std::uint64_t>(state.plans.size()));
    line += kSeparator;
    line += "evidence=" + to_decimal(static_cast<std::uint64_t>(state.evidence.size()));
    line += kSeparator;
    line += "decisions=" + to_decimal(static_cast<std::uint64_t>(state.decisions.size()));
    line += kSeparator;
    line += "unresolved=" + to_decimal(static_cast<std::uint64_t>(state.unresolved_attempts.size()));
    writer.record(line);
  }

  for (const std::pair<std::string, AuthorityRef>& entry : state.bindings.entries()) {
    std::string line("binding");
    line += kSeparator;
    line += "role=" + entry.first;
    line += kSeparator;
    line += "owner=";
    append_text(line, entry.second.owner());
    line += kSeparator;
    line += "identity=";
    append_text(line, entry.second.identity());
    line += kSeparator;
    line += "generation=";
    append_number(line, entry.second.generation().value());
    writer.record(line);
  }

  for (const CoolingScope& scope : state.scopes) {
    const ThermalEnvelope& envelope = scope.policy.envelope;
    auto quantity = [](std::string& line, std::string_view key, const DeclaredQuantity& value) {
      line += kSeparator;
      line += key;
      line += "=";
      append_number(line, value.value());
      line += ":";
      line += value.unit();
    };
    std::string line("scope");
    line += kSeparator;
    line += "id=" + scope.id.str();
    line += kSeparator;
    line += "kind=";
    append_token(line, scope.kind);
    line += kSeparator;
    line += "name=";
    append_text(line, scope.display_name);
    line += kSeparator;
    line += "bindings=" + to_decimal(static_cast<std::uint64_t>(scope.bindings.entries().size()));
    line += kSeparator;
    line += "deps=" + to_decimal(static_cast<std::uint64_t>(scope.dependencies.size()));
    line += kSeparator;
    line += "strict=" + to_decimal(static_cast<std::uint64_t>(scope.policy.strict_classes.size()));
    line += kSeparator;
    line += "reqs=" + to_decimal(static_cast<std::uint64_t>(scope.policy.requirements.size()));
    line += kSeparator;
    line += "dwell=";
    append_number(line, scope.policy.recovery_dwell.milliseconds());
    line += kSeparator;
    line += "hysteresis=";
    append_number(line, scope.policy.recovery_hysteresis.milliseconds());
    line += kSeparator;
    line += "service_floor=";
    append_token(line, scope.policy.service_severity_floor);
    quantity(line, "max_supply_temp", envelope.max_supply_temperature);
    quantity(line, "min_thermal_margin", envelope.min_thermal_margin);
    quantity(line, "min_flow", envelope.min_flow);
    quantity(line, "min_dp", envelope.min_differential_pressure);
    quantity(line, "demand", envelope.declared_demand);
    writer.record(line);

    for (const std::pair<std::string, AuthorityRef>& entry : scope.bindings.entries()) {
      std::string binding_line("scopeb");
      binding_line += kSeparator;
      binding_line += "scope=" + scope.id.str();
      binding_line += kSeparator;
      binding_line += "role=" + entry.first;
      binding_line += kSeparator;
      binding_line += "owner=";
      append_text(binding_line, entry.second.owner());
      binding_line += kSeparator;
      binding_line += "identity=";
      append_text(binding_line, entry.second.identity());
      binding_line += kSeparator;
      binding_line += "generation=";
      append_number(binding_line, entry.second.generation().value());
      writer.record(binding_line);
    }
    for (const FailureClass failure_class : scope.policy.strict_classes) {
      std::string class_line("scopeclass");
      class_line += kSeparator;
      class_line += "scope=" + scope.id.str();
      class_line += kSeparator;
      class_line += "class=";
      append_token(class_line, failure_class);
      writer.record(class_line);
    }
    for (const EvidenceRequirement& requirement : scope.policy.requirements) {
      std::string req_line("scopereq");
      req_line += kSeparator;
      req_line += "scope=" + scope.id.str();
      req_line += kSeparator;
      req_line += "channel=";
      append_token(req_line, requirement.channel);
      req_line += kSeparator;
      req_line += "window=";
      append_number(req_line, requirement.window.milliseconds());
      writer.record(req_line);
    }
    for (const ScopeDependency& dependency : scope.dependencies) {
      std::string dep_line("scopedep");
      dep_line += kSeparator;
      dep_line += "scope=" + scope.id.str();
      dep_line += kSeparator;
      dep_line += "upstream=" + dependency.upstream.str();
      dep_line += kSeparator;
      dep_line += "kind=";
      append_token(dep_line, dependency.kind);
      dep_line += kSeparator;
      dep_line += "share=";
      append_number(dep_line, dependency.share_parts_per_million);
      writer.record(dep_line);
    }
  }

  for (const CoolingFailure& failure : state.failures) {
    std::string line("failure");
    line += kSeparator;
    line += "id=" + failure.id.str();
    line += kSeparator;
    line += "scope=" + failure.scope.str();
    line += kSeparator;
    line += "class=";
    append_token(line, failure.failure_class);
    line += kSeparator;
    line += "confirmation=";
    append_token(line, failure.confirmation);
    line += kSeparator;
    line += "severity=";
    append_token(line, failure.severity);
    line += kSeparator;
    line += "urgency=";
    append_token(line, failure.urgency);
    line += kSeparator;
    line += "tti=";
    append_token(line, failure.time_to_impact);
    line += kSeparator;
    line += "at=";
    append_clock(line, failure.confirmed_at);
    line += kSeparator;
    line += "basis=" + to_decimal(static_cast<std::uint64_t>(failure.basis.size()));
    line += kSeparator;
    line += "shared_source=";
    line += failure.shared_source.empty() ? std::string() : failure.shared_source.str();
    line += kSeparator;
    line += "rationale=";
    append_text(line, failure.rationale);
    writer.record(line);

    for (std::size_t index = 0; index < failure.basis.size(); ++index) {
      std::string basis_line("failurebasis");
      basis_line += kSeparator;
      basis_line += "failure=" + failure.id.str();
      basis_line += kSeparator;
      basis_line += "observation=" + failure.basis[index].str();
      basis_line += kSeparator;
      basis_line += "ordinal=" + to_decimal(static_cast<std::uint64_t>(index));
      writer.record(basis_line);
    }
  }

  for (const ResponsePlan& plan : state.plans) {
    std::string line("plan");
    line += kSeparator;
    line += "id=" + plan.id.str();
    line += kSeparator;
    line += "scope=" + plan.scope.str();
    line += kSeparator;
    line += "lifecycle=";
    append_token(line, plan.lifecycle);
    line += kSeparator;
    line += "updated_at=";
    append_clock(line, plan.updated_at);
    line += kSeparator;
    line += "failures=" + to_decimal(static_cast<std::uint64_t>(plan.failures.size()));
    line += kSeparator;
    line += "eligible=" + to_decimal(static_cast<std::uint64_t>(plan.eligible.size()));
    line += kSeparator;
    line += "restrictions=" + to_decimal(static_cast<std::uint64_t>(plan.restrictions.size()));
    line += kSeparator;
    line += "attempts=" + to_decimal(static_cast<std::uint64_t>(plan.attempts.size()));
    line += kSeparator;
    line += "solicited=";
    append_token(line, plan.solicited_action);
    line += kSeparator;
    line += "has_solicited=";
    append_bool(line, plan.has_solicited_action);
    line += kSeparator;
    line += "explanation=" + to_decimal(static_cast<std::uint64_t>(plan.explanation.size()));
    writer.record(line);

    for (const FailureId& failure : plan.failures) {
      std::string plan_failure("planfailure");
      plan_failure += kSeparator;
      plan_failure += "plan=" + plan.id.str();
      plan_failure += kSeparator;
      plan_failure += "failure=" + failure.str();
      writer.record(plan_failure);
    }
    for (const ResponseEligibility& eligible : plan.eligible) {
      std::string eligible_line("planeligible");
      eligible_line += kSeparator;
      eligible_line += "plan=" + plan.id.str();
      eligible_line += kSeparator;
      eligible_line += "action=";
      append_token(eligible_line, eligible.action);
      eligible_line += kSeparator;
      eligible_line += "effect_class=";
      append_token(eligible_line, eligible.effect_class);
      eligible_line += kSeparator;
      eligible_line += "safety_critical=";
      append_bool(eligible_line, eligible.safety_critical);
      eligible_line += kSeparator;
      eligible_line += "rank=";
      append_number(eligible_line, static_cast<std::int64_t>(eligible.rank));
      eligible_line += kSeparator;
      eligible_line += "rule_id=";
      append_text(eligible_line, eligible.rule_id);
      writer.record(eligible_line);
    }
    for (const ProtectiveRestriction& restriction : plan.restrictions) {
      std::string restriction_line("restriction");
      restriction_line += kSeparator;
      restriction_line += "id=" + restriction.id.str();
      restriction_line += kSeparator;
      restriction_line += "scope=" + restriction.scope.str();
      restriction_line += kSeparator;
      restriction_line += "plan=" + restriction.plan.str();
      restriction_line += kSeparator;
      restriction_line += "kind=";
      append_token(restriction_line, restriction.kind);
      restriction_line += kSeparator;
      restriction_line += "ceiling=";
      append_number(restriction_line, restriction.ceiling.value());
      restriction_line += ":";
      restriction_line += restriction.ceiling.unit();
      restriction_line += kSeparator;
      restriction_line += "released_by=" +
                          to_decimal(static_cast<std::uint64_t>(restriction.released_by.size()));
      writer.record(restriction_line);
      for (const FailureId& failure : restriction.released_by) {
        std::string released_line("restrictionfailure");
        released_line += kSeparator;
        released_line += "restriction=" + restriction.id.str();
        released_line += kSeparator;
        released_line += "failure=" + failure.str();
        writer.record(released_line);
      }
    }
    for (const ResponseAttempt& attempt : plan.attempts) {
      std::string attempt_line("attempt");
      attempt_line += kSeparator;
      attempt_line += "id=" + attempt.id.str();
      attempt_line += kSeparator;
      attempt_line += "solicitation=" + attempt.solicitation.str();
      attempt_line += kSeparator;
      attempt_line += "ordinal=" + to_decimal(static_cast<std::uint64_t>(attempt.attempt.value()));
      attempt_line += kSeparator;
      attempt_line += "action=";
      append_token(attempt_line, attempt.action);
      attempt_line += kSeparator;
      attempt_line += "effect_class=";
      append_token(attempt_line, attempt.effect_class);
      attempt_line += kSeparator;
      attempt_line += "state=";
      append_token(attempt_line, attempt.state);
      attempt_line += kSeparator;
      attempt_line += "addressee=";
      append_text(attempt_line, attempt.addressee);
      attempt_line += kSeparator;
      attempt_line += "solicited_at=";
      append_clock(attempt_line, attempt.solicited_at);
      attempt_line += kSeparator;
      // An absent acknowledgement clock is written as an empty field, which is
      // this format's single spelling of "absent"; a negative clock is not a
      // canonical value and the decoder refuses it.
      attempt_line += "acknowledged_at=";
      append_clock(attempt_line, attempt.acknowledged_at);
      attempt_line += kSeparator;
      attempt_line += "updated_at=";
      append_clock(attempt_line, attempt.updated_at);
      attempt_line += kSeparator;
      attempt_line += "effect_observation=";
      attempt_line += attempt.effect_observation.empty() ? std::string()
                                                         : attempt.effect_observation.str();
      attempt_line += kSeparator;
      attempt_line += "verdict=";
      append_text(attempt_line, attempt.verdict);
      attempt_line += kSeparator;
      attempt_line += "adopted=";
      append_bool(attempt_line, attempt.adopted_after_restart);
      writer.record(attempt_line);
    }
  }

  for (const EvidenceAssessment& entry : state.evidence) {
    std::string line("evidence");
    line += kSeparator;
    line += "observation=" + entry.observation.str();
    line += kSeparator;
    line += "scope=" + entry.scope.str();
    line += kSeparator;
    line += "channel=";
    append_token(line, entry.channel);
    line += kSeparator;
    line += "status=";
    append_token(line, entry.status);
    line += kSeparator;
    line += "freshness=";
    append_token(line, entry.freshness);
    line += kSeparator;
    line += "availability=";
    append_token(line, entry.availability);
    line += kSeparator;
    line += "quality=";
    append_token(line, entry.quality);
    line += kSeparator;
    line += "age=";
    append_number(line, entry.age_milliseconds);
    line += kSeparator;
    line += "detail=";
    append_text(line, entry.detail);
    writer.record(line);
  }

  for (const ScopeDecision& decision : state.decisions) {
    std::string line("decision");
    line += kSeparator;
    line += "scope=" + decision.scope.str();
    line += kSeparator;
    line += "at=";
    append_clock(line, decision.evaluated_at);
    line += kSeparator;
    line += "severity=";
    append_token(line, decision.severity);
    line += kSeparator;
    line += "urgency=";
    append_token(line, decision.urgency);
    line += kSeparator;
    line += "tti=";
    append_token(line, decision.time_to_impact);
    line += kSeparator;
    line += "binding=";
    append_token(line, decision.binding_status);
    line += kSeparator;
    line += "recovery=";
    append_token(line, decision.recovery);
    line += kSeparator;
    line += "plan=";
    line += decision.has_plan ? decision.plan.str() : std::string();
    line += kSeparator;
    line += "confirmed=" + to_decimal(static_cast<std::uint64_t>(decision.confirmed_classes.size()));
    line += kSeparator;
    line += "suspected=" + to_decimal(static_cast<std::uint64_t>(decision.suspected_classes.size()));
    line += kSeparator;
    line += "contradicted=" +
            to_decimal(static_cast<std::uint64_t>(decision.contradicted_classes.size()));
    line += kSeparator;
    line += "unknown=" + to_decimal(static_cast<std::uint64_t>(decision.unknown_classes.size()));
    line += kSeparator;
    line += "failures=" + to_decimal(static_cast<std::uint64_t>(decision.failures.size()));
    line += kSeparator;
    line += "shared=" + to_decimal(static_cast<std::uint64_t>(decision.shared_sources.size()));
    line += kSeparator;
    line += "restrictions=" + to_decimal(static_cast<std::uint64_t>(decision.restrictions.size()));
    line += kSeparator;
    line += "gaps=" + to_decimal(static_cast<std::uint64_t>(decision.evidence_gaps.size()));
    line += kSeparator;
    line += "explanation=" + to_decimal(static_cast<std::uint64_t>(decision.explanation.size()));
    writer.record(line);

    auto class_bucket = [&](std::string_view bucket, const std::vector<FailureClass>& classes) {
      for (std::size_t index = 0; index < classes.size(); ++index) {
        std::string class_line("decisionclass");
        class_line += kSeparator;
        class_line += "scope=" + decision.scope.str();
        class_line += kSeparator;
        class_line += "bucket=";
        class_line += bucket;
        class_line += kSeparator;
        class_line += "class=";
        append_token(class_line, classes[index]);
        class_line += kSeparator;
        class_line += "ordinal=" + to_decimal(static_cast<std::uint64_t>(index));
        writer.record(class_line);
      }
    };
    class_bucket("confirmed", decision.confirmed_classes);
    class_bucket("suspected", decision.suspected_classes);
    class_bucket("contradicted", decision.contradicted_classes);
    class_bucket("unknown", decision.unknown_classes);

    for (std::size_t index = 0; index < decision.failures.size(); ++index) {
      std::string failure_line("decisionfailure");
      failure_line += kSeparator;
      failure_line += "scope=" + decision.scope.str();
      failure_line += kSeparator;
      failure_line += "failure=" + decision.failures[index].str();
      failure_line += kSeparator;
      failure_line += "ordinal=" + to_decimal(static_cast<std::uint64_t>(index));
      writer.record(failure_line);
    }
    for (std::size_t index = 0; index < decision.shared_sources.size(); ++index) {
      std::string shared_line("decisionshared");
      shared_line += kSeparator;
      shared_line += "scope=" + decision.scope.str();
      shared_line += kSeparator;
      shared_line += "source=" + decision.shared_sources[index].str();
      shared_line += kSeparator;
      shared_line += "ordinal=" + to_decimal(static_cast<std::uint64_t>(index));
      writer.record(shared_line);
    }
    for (std::size_t index = 0; index < decision.restrictions.size(); ++index) {
      std::string restriction_line("decisionrestriction");
      restriction_line += kSeparator;
      restriction_line += "scope=" + decision.scope.str();
      restriction_line += kSeparator;
      restriction_line += "restriction=" + decision.restrictions[index].str();
      restriction_line += kSeparator;
      restriction_line += "ordinal=" + to_decimal(static_cast<std::uint64_t>(index));
      writer.record(restriction_line);
    }
    for (std::size_t index = 0; index < decision.evidence_gaps.size(); ++index) {
      std::string gap_line("decisiongap");
      gap_line += kSeparator;
      gap_line += "scope=" + decision.scope.str();
      gap_line += kSeparator;
      gap_line += "channel=";
      append_token(gap_line, decision.evidence_gaps[index]);
      gap_line += kSeparator;
      gap_line += "ordinal=" + to_decimal(static_cast<std::uint64_t>(index));
      writer.record(gap_line);
    }
    for (std::size_t index = 0; index < decision.explanation.size(); ++index) {
      std::string text_line("decisiontext");
      text_line += kSeparator;
      text_line += "scope=" + decision.scope.str();
      text_line += kSeparator;
      text_line += "ordinal=" + to_decimal(static_cast<std::uint64_t>(index));
      text_line += kSeparator;
      text_line += "text=";
      append_text(text_line, decision.explanation[index]);
      writer.record(text_line);
    }
  }

  for (std::size_t index = 0; index < state.unresolved_attempts.size(); ++index) {
    std::string line("unresolved");
    line += kSeparator;
    line += "attempt=" + state.unresolved_attempts[index].str();
    line += kSeparator;
    line += "ordinal=" + to_decimal(static_cast<std::uint64_t>(index));
    writer.record(line);
  }

  return writer.finish();
}

Digest state_digest(const CoolingFailureState& state) {
  return digest_bytes(encode_state(state));
}

namespace {

/// One decoded record: its name and the fields it carried. Fields are read by
/// name exactly once, so a record cannot repeat a key the encoder writes once,
/// and a field the decoder does not know is refused rather than ignored.
class Record {
 public:
  static Result<Record> parse(std::string_view line, std::uint64_t line_number) {
    if (line.empty()) {
      return Error(ErrorCode::MalformedRecord, "record line is empty")
          .with_subject("line " + to_decimal(line_number));
    }
    if (line.find('\r') != std::string_view::npos || line.find('\0') != std::string_view::npos) {
      return Error(ErrorCode::MalformedRecord, "record line contains a carriage return or NUL")
          .with_subject("line " + to_decimal(line_number));
    }
    Record record;
    // A header line's fields after the name and the version are positional, not
    // key=value pairs, so the body vocabulary is not applied to them; read_header
    // reads them itself.
    const bool header_line = line.rfind(kHeaderRecord, 0) == 0;
    std::size_t start = 0;
    bool name_read = false;
    while (true) {
      const std::size_t next = line.find(kSeparator, start);
      const std::string_view field =
          next == std::string_view::npos ? line.substr(start) : line.substr(start, next - start);
      if (!name_read) {
        if (field.empty()) {
          return Error(ErrorCode::MalformedRecord, "record line starts with a separator")
              .with_subject("line " + to_decimal(line_number));
        }
        if (field.find('=') != std::string_view::npos) {
          return Error(ErrorCode::MalformedRecord, "record name contains '='")
              .with_subject(std::string(field.substr(0, 64)));
        }
        record.name_ = std::string(field);
        name_read = true;
      } else if (header_line) {
        // Positional header field: recorded verbatim, read positionally.
        record.fields_.emplace_back(std::string(), std::string(field));
      } else {
        if (field.empty()) {
          return Error(ErrorCode::MalformedRecord, "record line contains an empty field")
              .with_subject("line " + to_decimal(line_number));
        }
        const std::size_t equals = field.find('=');
        if (equals == std::string_view::npos || equals == 0) {
          return Error(ErrorCode::MalformedRecord, "field is not a key=value pair")
              .with_subject(std::string(field.substr(0, 64)));
        }
        record.fields_.emplace_back(std::string(field.substr(0, equals)),
                                    std::string(field.substr(equals + 1)));
      }
      if (next == std::string_view::npos) {
        break;
      }
      start = next + 1;
    }
    if (!name_read) {
      return Error(ErrorCode::MalformedRecord, "record line has no name");
    }
    return record;
  }

  const std::string& name() const noexcept { return name_; }

  Result<std::string_view> require(std::string_view key, bool allow_empty = false) {
    for (Field& field : fields_) {
      if (field.key != key) {
        continue;
      }
      if (field.consumed) {
        return Error(ErrorCode::MalformedRecord, "field appears twice in one record")
            .with_subject(std::string(key));
      }
      field.consumed = true;
      ++consumed_;
      if (field.value.empty() && !allow_empty) {
        return Error(ErrorCode::MissingField, "field is present but empty")
            .with_subject(std::string(key));
      }
      return std::string_view(field.value);
    }
    return Error(ErrorCode::MissingField, "required field is absent").with_subject(std::string(key));
  }

  Result<std::uint64_t> require_uint(std::string_view key, std::uint64_t max_value) {
    CFM_TRY(text, require(key));
    CFM_TRY(value, parse_uint64(text, max_value));
    return value;
  }

  Result<std::int64_t> require_int(std::string_view key, std::int64_t min_value,
                                   std::int64_t max_value) {
    CFM_TRY(text, require(key));
    CFM_TRY(value, parse_int64(text, min_value, max_value));
    return value;
  }

  /// A clock field. An empty field is this format's single spelling of "absent",
  /// which is how a record written before its clock was known renders; a negative
  /// clock is not a canonical value and is refused.
  Result<DecisionClock> require_clock(std::string_view key) {
    CFM_TRY(text, require(key, true));
    if (text.empty()) {
      return DecisionClock{};
    }
    CFM_TRY(value, parse_int64(text, 0, limits::kMaxTimestampMilliseconds));
    return DecisionClock::parse(value);
  }

  Result<DurationMilliseconds> require_duration(std::string_view key) {
    CFM_TRY(value, require_int(key, 0, limits::kMaxWindowMilliseconds));
    return DurationMilliseconds::parse(value);
  }

  template <class Id>
  Result<Id> require_id(std::string_view key) {
    CFM_TRY(text, require(key));
    return Id::parse(text);
  }

  /// An identity field that may legitimately be empty (an absent shared source,
  /// an attempt with no effect observation). Emptiness is the documented spelling
  /// of "absent", so it is read rather than refused.
  Result<std::string> require_optional_id(std::string_view key) {
    CFM_TRY(text, require(key, true));
    if (text.empty()) {
      return std::string();
    }
    CFM_TRY(parsed, ScopeId::parse(text));
    return std::string(parsed.str());
  }

  Result<std::string> require_text(std::string_view key, std::size_t max_bytes) {
    CFM_TRY(escaped, require(key, true));
    return unescape_text(escaped, max_bytes);
  }

  Result<bool> require_bool(std::string_view key) {
    CFM_TRY(text, require(key));
    if (text == "1") {
      return true;
    }
    if (text == "0") {
      return false;
    }
    return Error(ErrorCode::MalformedRecord, "boolean field is neither 0 nor 1")
        .with_subject(std::string(key));
  }

  Result<DeclaredQuantity> require_declared(std::string_view key) {
    CFM_TRY(text, require(key, true));
    if (text.empty()) {
      return DeclaredQuantity{};
    }
    const std::size_t colon = text.rfind(':');
    if (colon == std::string_view::npos) {
      return Error(ErrorCode::MalformedRecord, "declared quantity is not value:unit")
          .with_subject(std::string(key));
    }
    CFM_TRY(value, parse_int64(text.substr(0, colon), INT64_MIN, INT64_MAX));
    const std::string_view unit = text.substr(colon + 1);
    if (unit.empty()) {
      // An undeclared quantity has no unit. The encoder writes it as value: with
      // an empty unit, and the decoder accepts exactly that spelling rather than
      // treating an undeclared bound as a malformed one.
      if (value != 0) {
        return Error(ErrorCode::MalformedRecord,
                     "an undeclared quantity must be written as zero with an empty unit")
            .with_subject(std::string(key));
      }
      return DeclaredQuantity{};
    }
    CFM_TRY(quantity, DeclaredQuantity::make(value, unit));
    return quantity;
  }

  /// Every field must have been read by the time the record is finished.
  Result<void> finish() const {
    for (const Field& field : fields_) {
      if (!field.consumed) {
        return Error(ErrorCode::MalformedRecord,
                     "record carries a field the format does not define")
            .with_subject(field.key);
      }
    }
    return ok();
  }

 private:
  struct Field {
    std::string key;
    std::string value;
    bool consumed = false;
  };

  std::string name_;
  std::vector<Field> fields_;
  std::size_t consumed_ = 0;
};

/// One record name and the element it belongs to, so an out-of-order or
/// mis-parented record is reported instead of silently applied.
struct Expectation {
  const char* name;
  const char* parent;
};

/// Reads the whole body into records, checking the shape before any state is
/// built: every line must be a well-formed record, the last line must be the end
/// record, its count must match, and its digest must cover every preceding byte.
Result<std::vector<Record>> read_records(std::string_view text, std::size_t* records_end) {
  std::vector<Record> records;
  std::size_t line_start = 0;
  std::size_t line_number = 0;
  std::size_t body_end = std::string_view::npos;

  while (line_start <= text.size()) {
    const std::size_t next = text.find('\n', line_start);
    if (next == std::string_view::npos) {
      // The format always terminates the last line, so a body without a final
      // newline is truncated rather than merely unusual.
      return Error(ErrorCode::TruncatedInput, "the encoded state does not end with a newline")
          .with_subject("line " + to_decimal(static_cast<std::uint64_t>(line_number + 1)));
    }
    const std::string_view line = text.substr(line_start, next - line_start);
    ++line_number;
    if (line.empty()) {
      return Error(ErrorCode::MalformedRecord, "the encoded state contains an empty line")
          .with_subject("line " + to_decimal(static_cast<std::uint64_t>(line_number)));
    }
    if (line_number == 1) {
      // The header line names the format and its version; it is not a record and
      // is not counted.
      if (line.rfind(kHeaderRecord, 0) != 0) {
        return Error(ErrorCode::UnsupportedSchemaVersion,
                     "the encoded state does not begin with this format's header")
            .with_subject(std::string(line.substr(0, 64)));
      }
      line_start = next + 1;
      continue;
    }
    if (line.rfind(std::string(kEndRecord) + std::string(1, kSeparator), 0) == 0) {
      // The end record: its count and digest are checked against the body.
      body_end = line_start;
      const std::string_view tail = line.substr(kEndRecord.size() + 1);
      if (tail.find(kSeparator) == std::string_view::npos) {
        return Error(ErrorCode::MalformedRecord, "the end record is missing its digest");
      }
      const std::size_t split = tail.find(kSeparator);
      CFM_TRY(count, parse_uint64(tail.substr(0, split), UINT64_MAX));
      CFM_TRY(digest, Digest::parse_hex(tail.substr(split + 1)));
      if (count != records.size()) {
        // Neither the header nor the counts record is a counted record, so the end
        // record's count must equal exactly the body records that preceded it.
        return Error(ErrorCode::CountMismatch,
                     "the end record's count disagrees with the records that were read")
            .with_subject("declared " + to_decimal(count) + ", read " +
                          to_decimal(static_cast<std::uint64_t>(records.size())));
      }
      const Digest computed = digest_bytes(text.substr(0, body_end));
      if (!(computed == digest)) {
        return Error(ErrorCode::DigestMismatch,
                     "the body digest does not match the digest recorded at the end")
            .with_subject(digest.to_hex());
      }
      if (records_end != nullptr) {
        *records_end = body_end;
      }
      // Nothing may follow the end record but its own newline.
      if (next + 1 != text.size()) {
        return Error(ErrorCode::MalformedRecord, "content follows the end record");
      }
      return records;
    }
    CFM_TRY(record, Record::parse(line, static_cast<std::uint64_t>(line_number)));
    records.push_back(std::move(record));
    line_start = next + 1;
  }
  return Error(ErrorCode::TruncatedInput, "the encoded state has no end record");
}

/// Reads the header line's own fields.
Result<void> read_header(std::string_view header, CoolingFailureState& state) {
  const std::size_t first = header.find(kSeparator);
  if (first == std::string_view::npos) {
    return Error(ErrorCode::MalformedRecord, "the header line carries no version");
  }
  const std::size_t second = header.find(kSeparator, first + 1);
  const std::string_view version =
      second == std::string_view::npos ? header.substr(first + 1)
                                       : header.substr(first + 1, second - first - 1);
  // The version field is read as a field only when it carries a key; the encoder
  // writes it bare, so a version that is not a canonical decimal number is
  // refused here rather than being mistaken for a field of the body vocabulary.
  if (version.find('=') != std::string_view::npos) {
    return Error(ErrorCode::MalformedRecord, "the header version must not be a key=value field")
        .with_subject(std::string(version.substr(0, 64)));
  }
  CFM_TRY(parsed_version, parse_uint64(version, UINT32_MAX));
  if (parsed_version != kFormatVersion) {
    return Error(ErrorCode::UnsupportedSchemaVersion,
                 "the encoded state was written by an incompatible format version")
        .with_subject("declared " + to_decimal(parsed_version) + ", supported " +
                      to_decimal(static_cast<std::uint64_t>(kFormatVersion)));
  }
  if (second == std::string_view::npos) {
    return Error(ErrorCode::MalformedRecord, "the header line carries no generation fields");
  }
  // The header's remaining fields are read positionally rather than by the record
  // reader, because the header's first two fields are the format name and version
  // and the reader is the vocabulary of the body's records.
  const std::string_view rest = header.substr(second + 1);
  std::vector<std::string_view> fields;
  std::size_t start = 0;
  while (true) {
    const std::size_t next = rest.find(kSeparator, start);
    fields.push_back(next == std::string_view::npos ? rest.substr(start) : rest.substr(start, next - start));
    if (next == std::string_view::npos) {
      break;
    }
    start = next + 1;
  }
  if (fields.size() != 3) {
    return Error(ErrorCode::MalformedRecord, "the header line must carry generation, parent and clock")
        .with_subject(std::string(header.substr(0, 96)));
  }
  auto number_after = [&](std::string_view field, std::string_view key,
                          std::int64_t min_value, std::int64_t max_value) -> Result<std::int64_t> {
    if (field.rfind(key, 0) != 0) {
      return Error(ErrorCode::MalformedRecord, "the header field has an unexpected name")
          .with_subject(std::string(field.substr(0, 64)));
    }
    return parse_int64(field.substr(key.size()), min_value, max_value);
  };
  CFM_TRY(generation, number_after(fields[0], "generation=", 0, INT64_MAX));
  CFM_TRY(parent, number_after(fields[1], "parent=", 0, INT64_MAX));
  CFM_TRY(clock_text, parse_int64(fields[2].substr(std::string_view("clock=").size()), 0,
                                  limits::kMaxTimestampMilliseconds));
  const std::int64_t clock = clock_text;
  state.generation = StateGeneration(static_cast<std::uint64_t>(generation));
  state.parent_generation = StateGeneration(static_cast<std::uint64_t>(parent));
  state.evaluated_at = DecisionClock(clock);
  return ok();
}

}  // namespace

Result<CoolingFailureState> decode_state(std::string_view text) {
  if (text.empty()) {
    return Error(ErrorCode::EmptyInput, "the encoded state is empty");
  }
  if (text.size() > limits::kMaxGenerationBytes) {
    return Error(ErrorCode::LimitExceeded, "the encoded state exceeds the accepted size bound");
  }
  CoolingFailureState state;
  const std::size_t header_end = text.find('\n');
  if (header_end == std::string_view::npos) {
    return Error(ErrorCode::TruncatedInput, "the encoded state has no header line");
  }
  CFM_TRYV(read_header(text.substr(0, header_end), state));

  std::size_t records_end = 0;
  CFM_TRY(records, read_records(text, &records_end));
  (void)records_end;

  // The records are applied in the order the encoder emits them, and every group
  // is checked for the shape it must have: a parent record before its children, a
  // count record whose declaration matches what follows, and no record outside the
  // format's vocabulary.
  std::size_t index = 0;
  std::size_t expected_bindings = 0;
  std::size_t expected_scopes = 0;
  std::size_t expected_failures = 0;
  std::size_t expected_plans = 0;
  std::size_t expected_evidence = 0;
  std::size_t expected_decisions = 0;
  std::size_t expected_unresolved = 0;
  bool head_read = false;

  auto next_record = [&](std::string_view name) -> Result<const Record*> {
    if (index >= records.size()) {
      return Error(ErrorCode::TruncatedInput, "the record stream ended before the state was complete")
          .with_subject(std::string(name));
    }
    if (records[index].name() != name) {
      return Error(ErrorCode::MalformedRecord, "record appears out of order")
          .with_subject("expected " + std::string(name) + ", found " + records[index].name());
    }
    return &records[index++];
  };

  // The count record.
  {
    const Record& record = records[index];
    if (record.name() != "state") {
      return Error(ErrorCode::MalformedRecord, "the first record must declare the table sizes")
          .with_subject(record.name());
    }
    Record counts = record;
    CFM_TRY(bindings, counts.require_uint("bindings", limits::kMaxSolicitationCount));
    CFM_TRY(scopes, counts.require_uint("scopes", limits::kMaxScopeCount));
    CFM_TRY(failures, counts.require_uint("failures", limits::kMaxFailureCount));
    CFM_TRY(plans, counts.require_uint("plans", limits::kMaxScopeCount));
    CFM_TRY(evidence, counts.require_uint("evidence", limits::kMaxObservationCount));
    CFM_TRY(decisions, counts.require_uint("decisions", limits::kMaxScopeCount));
    CFM_TRY(unresolved, counts.require_uint("unresolved", limits::kMaxAttemptSetCount));
    CFM_TRYV(counts.finish());
    expected_bindings = static_cast<std::size_t>(bindings);
    expected_scopes = static_cast<std::size_t>(scopes);
    expected_failures = static_cast<std::size_t>(failures);
    expected_plans = static_cast<std::size_t>(plans);
    expected_evidence = static_cast<std::size_t>(evidence);
    expected_decisions = static_cast<std::size_t>(decisions);
    expected_unresolved = static_cast<std::size_t>(unresolved);
    // The counts record is consumed here and is not part of the body vocabulary.
    ++index;
    head_read = true;
  }
  (void)head_read;

  // Bindings.
  for (std::size_t counter = 0; counter < expected_bindings; ++counter) {
    const Record& record = records[index++];
    if (record.name() != "binding") {
      return Error(ErrorCode::MalformedRecord, "expected a binding record").with_subject(record.name());
    }
    Record reader = record;
    CFM_TRY(role, reader.require("role", false));
    CFM_TRY(owner, reader.require_text("owner", limits::kMaxExternalKindBytes));
    CFM_TRY(identity, reader.require_text("identity", limits::kMaxExternalIdentityBytes));
    CFM_TRY(generation, reader.require_uint("generation", UINT64_MAX));
    CFM_TRYV(reader.finish());
    CFM_TRY(reference, AuthorityRef::make(owner, identity, ExternalGeneration(generation)));
    CFM_TRYV(state.bindings.set(role, reference));
  }

  // Scopes and everything that belongs to one.
  for (std::size_t counter = 0; counter < expected_scopes; ++counter) {
    if (index >= records.size() || records[index].name() != "scope") {
      return Error(ErrorCode::MalformedRecord, "expected a scope record")
          .with_subject(index < records.size() ? records[index].name() : "end of stream");
    }
    Record reader = records[index++];
    CoolingScope scope;
    CFM_TRY(id, reader.require_id<ScopeId>("id"));
    scope.id = id;
    CFM_TRY(kind, reader.require("kind"));
    CFM_TRY(parsed_kind, scope_kind_from_token(kind));
    scope.kind = parsed_kind;
    CFM_TRY(name, reader.require_text("name", limits::kMaxDisplayNameBytes));
    scope.display_name = name;
    CFM_TRY(bindings, reader.require_uint("bindings", limits::kMaxSolicitationCount));
    CFM_TRY(deps, reader.require_uint("deps", limits::kMaxScopeDependencyCount));
    CFM_TRY(strict, reader.require_uint("strict", limits::kMaxFailureClassCount));
    CFM_TRY(reqs, reader.require_uint("reqs", limits::kMaxRecoveryDemandCount));
    CFM_TRY(dwell, reader.require_duration("dwell"));
    CFM_TRY(hysteresis, reader.require_duration("hysteresis"));
    CFM_TRY(floor, reader.require("service_floor"));
    CFM_TRY(parsed_floor, severity_from_token(floor));
    scope.policy.service_severity_floor = parsed_floor;
    scope.policy.recovery_dwell = dwell;
    scope.policy.recovery_hysteresis = hysteresis;
    CFM_TRY(max_supply, reader.require_declared("max_supply_temp"));
    CFM_TRY(min_margin, reader.require_declared("min_thermal_margin"));
    CFM_TRY(min_flow, reader.require_declared("min_flow"));
    CFM_TRY(min_dp, reader.require_declared("min_dp"));
    CFM_TRY(demand, reader.require_declared("demand"));
    scope.policy.envelope.max_supply_temperature = max_supply;
    scope.policy.envelope.min_thermal_margin = min_margin;
    scope.policy.envelope.min_flow = min_flow;
    scope.policy.envelope.min_differential_pressure = min_dp;
    scope.policy.envelope.declared_demand = demand;
    CFM_TRYV(reader.finish());

    for (std::size_t child = 0; child < static_cast<std::size_t>(bindings); ++child) {
      if (index >= records.size() || records[index].name() != "scopeb") {
        return Error(ErrorCode::MalformedRecord, "expected a scope binding record");
      }
      Record binding_reader = records[index++];
      CFM_TRY(scope_id, binding_reader.require_id<ScopeId>("scope"));
      if (!(scope_id == scope.id)) {
        return Error(ErrorCode::MalformedRecord, "a scope binding names another scope")
            .with_subject(scope_id.str());
      }
      CFM_TRY(role, binding_reader.require("role", false));
      CFM_TRY(owner, binding_reader.require_text("owner", limits::kMaxExternalKindBytes));
      CFM_TRY(identity, binding_reader.require_text("identity", limits::kMaxExternalIdentityBytes));
      CFM_TRY(generation, binding_reader.require_uint("generation", UINT64_MAX));
      CFM_TRYV(binding_reader.finish());
      CFM_TRY(reference, AuthorityRef::make(owner, identity, ExternalGeneration(generation)));
      CFM_TRYV(scope.bindings.set(role, reference));
    }
    for (std::size_t child = 0; child < static_cast<std::size_t>(strict); ++child) {
      if (index >= records.size() || records[index].name() != "scopeclass") {
        return Error(ErrorCode::MalformedRecord, "expected a strict-class record");
      }
      Record class_reader = records[index++];
      CFM_TRY(scope_id, class_reader.require_id<ScopeId>("scope"));
      if (!(scope_id == scope.id)) {
        return Error(ErrorCode::MalformedRecord, "a strict-class record names another scope")
            .with_subject(scope_id.str());
      }
      CFM_TRY(class_token, class_reader.require("class"));
      CFM_TRY(parsed_class, failure_class_from_token(class_token));
      CFM_TRYV(class_reader.finish());
      scope.policy.strict_classes.push_back(parsed_class);
    }
    for (std::size_t child = 0; child < static_cast<std::size_t>(reqs); ++child) {
      if (index >= records.size() || records[index].name() != "scopereq") {
        return Error(ErrorCode::MalformedRecord, "expected an evidence-requirement record");
      }
      Record requirement_reader = records[index++];
      CFM_TRY(scope_id, requirement_reader.require_id<ScopeId>("scope"));
      if (!(scope_id == scope.id)) {
        return Error(ErrorCode::MalformedRecord, "an evidence requirement names another scope")
            .with_subject(scope_id.str());
      }
      CFM_TRY(channel_token, requirement_reader.require("channel"));
      CFM_TRY(channel, observation_channel_from_token(channel_token));
      CFM_TRY(window, requirement_reader.require_duration("window"));
      CFM_TRYV(requirement_reader.finish());
      scope.policy.requirements.push_back(EvidenceRequirement{channel, window});
    }
    for (std::size_t child = 0; child < static_cast<std::size_t>(deps); ++child) {
      if (index >= records.size() || records[index].name() != "scopedep") {
        return Error(ErrorCode::MalformedRecord, "expected a dependency record");
      }
      Record dependency_reader = records[index++];
      CFM_TRY(scope_id, dependency_reader.require_id<ScopeId>("scope"));
      if (!(scope_id == scope.id)) {
        return Error(ErrorCode::MalformedRecord, "a dependency record names another scope")
            .with_subject(scope_id.str());
      }
      CFM_TRY(upstream, dependency_reader.require_id<ScopeId>("upstream"));
      CFM_TRY(kind_token, dependency_reader.require("kind"));
      CFM_TRY(parsed_dependency, dependency_kind_from_token(kind_token));
      CFM_TRY(share, dependency_reader.require_int("share", 0, 1000000));
      CFM_TRYV(dependency_reader.finish());
      ScopeDependency dependency;
      dependency.upstream = upstream;
      dependency.kind = parsed_dependency;
      dependency.share_parts_per_million = share;
      scope.dependencies.push_back(dependency);
    }
    state.scopes.push_back(std::move(scope));
  }

  // Failures and their basis lists.
  for (std::size_t counter = 0; counter < expected_failures; ++counter) {
    if (index >= records.size() || records[index].name() != "failure") {
      return Error(ErrorCode::MalformedRecord, "expected a failure record");
    }
    Record reader = records[index++];
    CoolingFailure failure;
    CFM_TRY(id, reader.require_id<FailureId>("id"));
    failure.id = id;
    CFM_TRY(scope_id, reader.require_id<ScopeId>("scope"));
    failure.scope = scope_id;
    CFM_TRY(class_token, reader.require("class"));
    CFM_TRY(parsed_class, failure_class_from_token(class_token));
    failure.failure_class = parsed_class;
    CFM_TRY(confirmation_token, reader.require("confirmation"));
    CFM_TRY(parsed_confirmation, confirmation_state_from_token(confirmation_token));
    failure.confirmation = parsed_confirmation;
    CFM_TRY(severity_token, reader.require("severity"));
    CFM_TRY(parsed_severity, severity_from_token(severity_token));
    failure.severity = parsed_severity;
    CFM_TRY(urgency_token, reader.require("urgency"));
    CFM_TRY(parsed_urgency, urgency_from_token(urgency_token));
    failure.urgency = parsed_urgency;
    CFM_TRY(tti_token, reader.require("tti"));
    CFM_TRY(parsed_tti, time_to_impact_from_token(tti_token));
    failure.time_to_impact = parsed_tti;
    CFM_TRY(at, reader.require_clock("at"));
    failure.confirmed_at = at;
    CFM_TRY(basis, reader.require_uint("basis", limits::kMaxObservationPerScope));
    CFM_TRY(shared, reader.require("shared_source", true));
    if (!shared.empty()) {
      CFM_TRY(parsed_shared, ScopeId::parse(shared));
      failure.shared_source = parsed_shared;
    }
    CFM_TRY(rationale, reader.require_text("rationale", limits::kMaxTextBytes));
    failure.rationale = rationale;
    CFM_TRYV(reader.finish());
    for (std::size_t child = 0; child < static_cast<std::size_t>(basis); ++child) {
      if (index >= records.size() || records[index].name() != "failurebasis") {
        return Error(ErrorCode::MalformedRecord, "expected a failure-basis record");
      }
      Record basis_reader = records[index++];
      CFM_TRY(basis_failure, basis_reader.require_id<FailureId>("failure"));
      if (!(basis_failure == failure.id)) {
        return Error(ErrorCode::MalformedRecord, "a basis record names another failure")
            .with_subject(basis_failure.str());
      }
      CFM_TRY(observation, basis_reader.require_id<ObservationId>("observation"));
      CFM_TRY(ordinal, basis_reader.require_uint("ordinal", limits::kMaxObservationPerScope));
      if (ordinal != failure.basis.size()) {
        return Error(ErrorCode::MalformedRecord, "a basis record carries an out-of-sequence ordinal")
            .with_subject(to_decimal(ordinal));
      }
      CFM_TRYV(basis_reader.finish());
      failure.basis.push_back(observation);
    }
    state.failures.push_back(std::move(failure));
  }

  // Plans and everything that belongs to one.
  for (std::size_t counter = 0; counter < expected_plans; ++counter) {
    if (index >= records.size() || records[index].name() != "plan") {
      return Error(ErrorCode::MalformedRecord, "expected a plan record");
    }
    Record reader = records[index++];
    ResponsePlan plan;
    CFM_TRY(id, reader.require_id<PlanId>("id"));
    plan.id = id;
    CFM_TRY(scope_id, reader.require_id<ScopeId>("scope"));
    plan.scope = scope_id;
    CFM_TRY(lifecycle_token, reader.require("lifecycle"));
    CFM_TRY(parsed_lifecycle, plan_lifecycle_from_token(lifecycle_token));
    plan.lifecycle = parsed_lifecycle;
    CFM_TRY(updated, reader.require_clock("updated_at"));
    plan.updated_at = updated;
    CFM_TRY(failures, reader.require_uint("failures", limits::kMaxFailureCount));
    CFM_TRY(eligible, reader.require_uint("eligible", limits::kMaxPlanEligibilityCount));
    CFM_TRY(restrictions, reader.require_uint("restrictions", limits::kMaxRestrictionCount));
    CFM_TRY(attempts, reader.require_uint("attempts", limits::kMaxAttemptCount));
    CFM_TRY(solicited_token, reader.require("solicited"));
    CFM_TRY(parsed_solicited, response_action_from_token(solicited_token));
    plan.solicited_action = parsed_solicited;
    CFM_TRY(has_solicited, reader.require_bool("has_solicited"));
    plan.has_solicited_action = has_solicited;
    CFM_TRY(explanation_count, reader.require_uint("explanation", limits::kMaxDecisionEntryCount));
    CFM_TRYV(reader.finish());
    (void)explanation_count;

    for (std::size_t child = 0; child < static_cast<std::size_t>(failures); ++child) {
      if (index >= records.size() || records[index].name() != "planfailure") {
        return Error(ErrorCode::MalformedRecord, "expected a plan-failure record");
      }
      Record failure_reader = records[index++];
      CFM_TRY(plan_id, failure_reader.require_id<PlanId>("plan"));
      if (!(plan_id == plan.id)) {
        return Error(ErrorCode::MalformedRecord, "a plan-failure record names another plan")
            .with_subject(plan_id.str());
      }
      CFM_TRY(failure, failure_reader.require_id<FailureId>("failure"));
      CFM_TRYV(failure_reader.finish());
      plan.failures.push_back(failure);
    }
    for (std::size_t child = 0; child < static_cast<std::size_t>(eligible); ++child) {
      if (index >= records.size() || records[index].name() != "planeligible") {
        return Error(ErrorCode::MalformedRecord, "expected an eligibility record");
      }
      Record eligible_reader = records[index++];
      CFM_TRY(plan_id, eligible_reader.require_id<PlanId>("plan"));
      if (!(plan_id == plan.id)) {
        return Error(ErrorCode::MalformedRecord, "an eligibility record names another plan")
            .with_subject(plan_id.str());
      }
      ResponseEligibility entry;
      CFM_TRY(action_token, eligible_reader.require("action"));
      CFM_TRY(action, response_action_from_token(action_token));
      entry.action = action;
      CFM_TRY(effect_token, eligible_reader.require("effect_class"));
      CFM_TRY(effect, effect_class_from_token(effect_token));
      entry.effect_class = effect;
      CFM_TRY(safety, eligible_reader.require_bool("safety_critical"));
      entry.safety_critical = safety;
      CFM_TRY(rank, eligible_reader.require_int("rank", INT32_MIN, INT32_MAX));
      entry.rank = static_cast<std::int32_t>(rank);
      CFM_TRY(rule_id, eligible_reader.require_text("rule_id", limits::kMaxIdentifierBytes));
      entry.rule_id = rule_id;
      CFM_TRYV(eligible_reader.finish());
      plan.eligible.push_back(std::move(entry));
    }
    for (std::size_t child = 0; child < static_cast<std::size_t>(restrictions); ++child) {
      if (index >= records.size() || records[index].name() != "restriction") {
        return Error(ErrorCode::MalformedRecord, "expected a restriction record");
      }
      Record restriction_reader = records[index++];
      ProtectiveRestriction restriction;
      CFM_TRY(restriction_identity, restriction_reader.require_id<RestrictionId>("id"));
      restriction.id = restriction_identity;
      CFM_TRY(restriction_scope_identity, restriction_reader.require_id<ScopeId>("scope"));
      restriction.scope = restriction_scope_identity;
      CFM_TRY(restriction_plan_identity, restriction_reader.require_id<PlanId>("plan"));
      restriction.plan = restriction_plan_identity;
      CFM_TRY(kind_token, restriction_reader.require("kind"));
      CFM_TRY(kind, restriction_kind_from_token(kind_token));
      restriction.kind = kind;
      CFM_TRY(ceiling, restriction_reader.require_declared("ceiling"));
      restriction.ceiling = ceiling;
      CFM_TRY(released, restriction_reader.require_uint("released_by", limits::kMaxFailureCount));
      CFM_TRYV(restriction_reader.finish());
      for (std::size_t released_index = 0; released_index < static_cast<std::size_t>(released);
           ++released_index) {
        if (index >= records.size() || records[index].name() != "restrictionfailure") {
          return Error(ErrorCode::MalformedRecord, "expected a restriction-failure record");
        }
        Record released_reader = records[index++];
        CFM_TRY(released_restriction, released_reader.require_id<RestrictionId>("restriction"));
        if (!(released_restriction == restriction.id)) {
          return Error(ErrorCode::MalformedRecord,
                       "a restriction-failure record names another restriction")
              .with_subject(released_restriction.str());
        }
        CFM_TRY(failure, released_reader.require_id<FailureId>("failure"));
        CFM_TRYV(released_reader.finish());
        restriction.released_by.push_back(failure);
      }
      plan.restrictions.push_back(std::move(restriction));
    }
    for (std::size_t child = 0; child < static_cast<std::size_t>(attempts); ++child) {
      if (index >= records.size() || records[index].name() != "attempt") {
        return Error(ErrorCode::MalformedRecord, "expected an attempt record");
      }
      Record attempt_reader = records[index++];
      ResponseAttempt attempt;
      CFM_TRY(attempt_id, attempt_reader.require_id<AttemptId>("id"));
      attempt.id = attempt_id;
      CFM_TRY(solicitation, attempt_reader.require_id<MutationId>("solicitation"));
      attempt.solicitation = solicitation;
      CFM_TRY(ordinal, attempt_reader.require_uint("ordinal", UINT32_MAX));
      CFM_TRY(parsed_ordinal, AttemptOrdinal::parse(static_cast<std::uint32_t>(ordinal)));
      attempt.attempt = parsed_ordinal;
      CFM_TRY(action_token, attempt_reader.require("action"));
      CFM_TRY(action, response_action_from_token(action_token));
      attempt.action = action;
      CFM_TRY(effect_token, attempt_reader.require("effect_class"));
      CFM_TRY(effect, effect_class_from_token(effect_token));
      attempt.effect_class = effect;
      CFM_TRY(state_token, attempt_reader.require("state"));
      CFM_TRY(attempt_state, attempt_state_from_token(state_token));
      attempt.state = attempt_state;
      CFM_TRY(addressee, attempt_reader.require_text("addressee", limits::kMaxExternalKindBytes));
      attempt.addressee = addressee;
      CFM_TRY(solicited_at, attempt_reader.require_clock("solicited_at"));
      attempt.solicited_at = solicited_at;
      CFM_TRY(acknowledged_text, attempt_reader.require("acknowledged_at", true));
      if (!acknowledged_text.empty()) {
        CFM_TRY(acknowledged_at,
                parse_int64(acknowledged_text, 0, limits::kMaxTimestampMilliseconds));
        attempt.acknowledged_at = DecisionClock(acknowledged_at);
      }
      CFM_TRY(updated_at, attempt_reader.require_clock("updated_at"));
      attempt.updated_at = updated_at;
      CFM_TRY(effect_observation, attempt_reader.require("effect_observation", true));
      if (!effect_observation.empty()) {
        CFM_TRY(parsed_effect, ObservationId::parse(effect_observation));
        attempt.effect_observation = parsed_effect;
      }
      CFM_TRY(verdict, attempt_reader.require_text("verdict", limits::kMaxWitnessBytes));
      attempt.verdict = verdict;
      CFM_TRY(adopted, attempt_reader.require_bool("adopted"));
      attempt.adopted_after_restart = adopted;
      CFM_TRYV(attempt_reader.finish());
      plan.attempts.push_back(std::move(attempt));
    }
    state.plans.push_back(std::move(plan));
  }

  // Evidence.
  for (std::size_t counter = 0; counter < expected_evidence; ++counter) {
    if (index >= records.size() || records[index].name() != "evidence") {
      return Error(ErrorCode::MalformedRecord, "expected an evidence record");
    }
    Record reader = records[index++];
    EvidenceAssessment entry;
    CFM_TRY(observation, reader.require_id<ObservationId>("observation"));
    entry.observation = observation;
    CFM_TRY(scope_id, reader.require_id<ScopeId>("scope"));
    entry.scope = scope_id;
    CFM_TRY(channel_token, reader.require("channel"));
    CFM_TRY(channel, observation_channel_from_token(channel_token));
    entry.channel = channel;
    CFM_TRY(status_token, reader.require("status"));
    CFM_TRY(status, evidence_status_from_token(status_token));
    entry.status = status;
    CFM_TRY(freshness_token, reader.require("freshness"));
    CFM_TRY(freshness, freshness_from_token(freshness_token));
    entry.freshness = freshness;
    CFM_TRY(availability_token, reader.require("availability"));
    CFM_TRY(availability, availability_from_token(availability_token));
    entry.availability = availability;
    CFM_TRY(quality_token, reader.require("quality"));
    CFM_TRY(quality, observation_quality_from_token(quality_token));
    entry.quality = quality;
    CFM_TRY(age, reader.require_int("age", -limits::kMaxTimestampMilliseconds,
                                    limits::kMaxTimestampMilliseconds));
    entry.age_milliseconds = age;
    CFM_TRY(detail, reader.require_text("detail", limits::kMaxWitnessBytes));
    entry.detail = detail;
    CFM_TRYV(reader.finish());
    state.evidence.push_back(std::move(entry));
  }

  // Decisions and their lists.
  for (std::size_t counter = 0; counter < expected_decisions; ++counter) {
    if (index >= records.size() || records[index].name() != "decision") {
      return Error(ErrorCode::MalformedRecord, "expected a decision record");
    }
    Record reader = records[index++];
    ScopeDecision decision;
    CFM_TRY(scope_id, reader.require_id<ScopeId>("scope"));
    decision.scope = scope_id;
    CFM_TRY(at, reader.require_clock("at"));
    decision.evaluated_at = at;
    CFM_TRY(severity_token, reader.require("severity"));
    CFM_TRY(severity, severity_from_token(severity_token));
    decision.severity = severity;
    CFM_TRY(urgency_token, reader.require("urgency"));
    CFM_TRY(urgency, urgency_from_token(urgency_token));
    decision.urgency = urgency;
    CFM_TRY(tti_token, reader.require("tti"));
    CFM_TRY(tti, time_to_impact_from_token(tti_token));
    decision.time_to_impact = tti;
    CFM_TRY(binding_token, reader.require("binding"));
    CFM_TRY(binding, binding_status_from_token(binding_token));
    decision.binding_status = binding;
    CFM_TRY(recovery_token, reader.require("recovery"));
    CFM_TRY(recovery, recovery_decision_from_token(recovery_token));
    decision.recovery = recovery;
    CFM_TRY(plan_text, reader.require("plan", true));
    if (!plan_text.empty()) {
      CFM_TRY(plan_id, PlanId::parse(plan_text));
      decision.plan = plan_id;
      decision.has_plan = true;
    }
    CFM_TRY(confirmed, reader.require_uint("confirmed", limits::kMaxFailureClassCount));
    CFM_TRY(suspected, reader.require_uint("suspected", limits::kMaxFailureClassCount));
    CFM_TRY(contradicted, reader.require_uint("contradicted", limits::kMaxFailureClassCount));
    CFM_TRY(unknown, reader.require_uint("unknown", limits::kMaxFailureClassCount));
    CFM_TRY(failures, reader.require_uint("failures", limits::kMaxFailureCount));
    CFM_TRY(shared, reader.require_uint("shared", limits::kMaxSharedSourceCount));
    CFM_TRY(restrictions, reader.require_uint("restrictions", limits::kMaxRestrictionScopeCount));
    CFM_TRY(gaps, reader.require_uint("gaps", limits::kMaxEvidenceGapCount));
    CFM_TRY(explanation_count,
            reader.require_uint("explanation", limits::kMaxDecisionEntryCount));
    CFM_TRYV(reader.finish());

    auto read_class_bucket = [&](std::string_view bucket,
                                 std::size_t count) -> Result<std::vector<FailureClass>> {
      std::vector<FailureClass> classes;
      for (std::size_t child = 0; child < count; ++child) {
        if (index >= records.size() || records[index].name() != "decisionclass") {
          return Error(ErrorCode::MalformedRecord, "expected a decision-class record");
        }
        Record class_reader = records[index++];
        CFM_TRY(class_scope, class_reader.require_id<ScopeId>("scope"));
        if (!(class_scope == decision.scope)) {
          return Error(ErrorCode::MalformedRecord, "a decision-class record names another scope")
              .with_subject(class_scope.str());
        }
        CFM_TRY(bucket_text, class_reader.require("bucket"));
        if (bucket_text != bucket) {
          return Error(ErrorCode::MalformedRecord, "a class record carries another bucket")
              .with_subject(std::string(bucket_text));
        }
        CFM_TRY(class_token, class_reader.require("class"));
        CFM_TRY(parsed, failure_class_from_token(class_token));
        CFM_TRY(ordinal, class_reader.require_uint("ordinal", limits::kMaxFailureClassCount));
        if (ordinal != classes.size()) {
          return Error(ErrorCode::MalformedRecord, "a class record carries an out-of-sequence ordinal");
        }
        CFM_TRYV(class_reader.finish());
        classes.push_back(parsed);
      }
      return classes;
    };

    CFM_TRY(confirmed_classes, read_class_bucket("confirmed", static_cast<std::size_t>(confirmed)));
    decision.confirmed_classes = confirmed_classes;
    CFM_TRY(suspected_classes, read_class_bucket("suspected", static_cast<std::size_t>(suspected)));
    decision.suspected_classes = suspected_classes;
    CFM_TRY(contradicted_classes,
            read_class_bucket("contradicted", static_cast<std::size_t>(contradicted)));
    decision.contradicted_classes = contradicted_classes;
    CFM_TRY(unknown_classes, read_class_bucket("unknown", static_cast<std::size_t>(unknown)));
    decision.unknown_classes = unknown_classes;

    for (std::size_t child = 0; child < static_cast<std::size_t>(failures); ++child) {
      if (index >= records.size() || records[index].name() != "decisionfailure") {
        return Error(ErrorCode::MalformedRecord, "expected a decision-failure record");
      }
      Record failure_reader = records[index++];
      CFM_TRY(failure_scope, failure_reader.require_id<ScopeId>("scope"));
      if (!(failure_scope == decision.scope)) {
        return Error(ErrorCode::MalformedRecord, "a decision-failure record names another scope")
            .with_subject(failure_scope.str());
      }
      CFM_TRY(failure, failure_reader.require_id<FailureId>("failure"));
      CFM_TRY(ordinal, failure_reader.require_uint("ordinal", limits::kMaxFailureCount));
      if (ordinal != decision.failures.size()) {
        return Error(ErrorCode::MalformedRecord, "a decision-failure record carries an out-of-sequence ordinal");
      }
      CFM_TRYV(failure_reader.finish());
      decision.failures.push_back(failure);
    }
    for (std::size_t child = 0; child < static_cast<std::size_t>(shared); ++child) {
      if (index >= records.size() || records[index].name() != "decisionshared") {
        return Error(ErrorCode::MalformedRecord, "expected a decision-shared-source record");
      }
      Record shared_reader = records[index++];
      CFM_TRY(shared_scope, shared_reader.require_id<ScopeId>("scope"));
      if (!(shared_scope == decision.scope)) {
        return Error(ErrorCode::MalformedRecord, "a decision-shared-source record names another scope")
            .with_subject(shared_scope.str());
      }
      CFM_TRY(source, shared_reader.require_id<ScopeId>("source"));
      CFM_TRY(ordinal, shared_reader.require_uint("ordinal", limits::kMaxSharedSourceCount));
      if (ordinal != decision.shared_sources.size()) {
        return Error(ErrorCode::MalformedRecord,
                     "a decision-shared-source record carries an out-of-sequence ordinal");
      }
      CFM_TRYV(shared_reader.finish());
      decision.shared_sources.push_back(source);
    }
    for (std::size_t child = 0; child < static_cast<std::size_t>(restrictions); ++child) {
      if (index >= records.size() || records[index].name() != "decisionrestriction") {
        return Error(ErrorCode::MalformedRecord, "expected a decision-restriction record");
      }
      Record restriction_reader = records[index++];
      CFM_TRY(restriction_scope, restriction_reader.require_id<ScopeId>("scope"));
      if (!(restriction_scope == decision.scope)) {
        return Error(ErrorCode::MalformedRecord, "a decision-restriction record names another scope")
            .with_subject(restriction_scope.str());
      }
      CFM_TRY(restriction, restriction_reader.require_id<RestrictionId>("restriction"));
      CFM_TRY(ordinal, restriction_reader.require_uint("ordinal", limits::kMaxRestrictionScopeCount));
      if (ordinal != decision.restrictions.size()) {
        return Error(ErrorCode::MalformedRecord,
                     "a decision-restriction record carries an out-of-sequence ordinal");
      }
      CFM_TRYV(restriction_reader.finish());
      decision.restrictions.push_back(restriction);
    }
    for (std::size_t child = 0; child < static_cast<std::size_t>(gaps); ++child) {
      if (index >= records.size() || records[index].name() != "decisiongap") {
        return Error(ErrorCode::MalformedRecord, "expected a decision-gap record");
      }
      Record gap_reader = records[index++];
      CFM_TRY(gap_scope, gap_reader.require_id<ScopeId>("scope"));
      if (!(gap_scope == decision.scope)) {
        return Error(ErrorCode::MalformedRecord, "a decision-gap record names another scope")
            .with_subject(gap_scope.str());
      }
      CFM_TRY(channel_token, gap_reader.require("channel"));
      CFM_TRY(channel, observation_channel_from_token(channel_token));
      CFM_TRY(ordinal, gap_reader.require_uint("ordinal", limits::kMaxEvidenceGapCount));
      if (ordinal != decision.evidence_gaps.size()) {
        return Error(ErrorCode::MalformedRecord, "a decision-gap record carries an out-of-sequence ordinal");
      }
      CFM_TRYV(gap_reader.finish());
      decision.evidence_gaps.push_back(channel);
    }
    for (std::size_t child = 0; child < static_cast<std::size_t>(explanation_count); ++child) {
      if (index >= records.size() || records[index].name() != "decisiontext") {
        return Error(ErrorCode::MalformedRecord, "expected a decision-text record");
      }
      Record text_reader = records[index++];
      CFM_TRY(text_scope, text_reader.require_id<ScopeId>("scope"));
      if (!(text_scope == decision.scope)) {
        return Error(ErrorCode::MalformedRecord, "a decision-text record names another scope")
            .with_subject(text_scope.str());
      }
      CFM_TRY(ordinal, text_reader.require_uint("ordinal", limits::kMaxDecisionEntryCount));
      if (ordinal != decision.explanation.size()) {
        return Error(ErrorCode::MalformedRecord, "a decision-text record carries an out-of-sequence ordinal");
      }
      CFM_TRY(explanation_line, text_reader.require_text("text", limits::kMaxTextBytes));
      CFM_TRYV(text_reader.finish());
      decision.explanation.push_back(explanation_line);
    }
    state.decisions.push_back(std::move(decision));
  }

  // Unresolved attempts.
  for (std::size_t counter = 0; counter < expected_unresolved; ++counter) {
    if (index >= records.size() || records[index].name() != "unresolved") {
      return Error(ErrorCode::MalformedRecord, "expected an unresolved-attempt record");
    }
    Record reader = records[index++];
    CFM_TRY(attempt, reader.require_id<AttemptId>("attempt"));
    CFM_TRY(ordinal, reader.require_uint("ordinal", limits::kMaxAttemptSetCount));
    if (ordinal != state.unresolved_attempts.size()) {
      return Error(ErrorCode::MalformedRecord, "an unresolved record carries an out-of-sequence ordinal");
    }
    CFM_TRYV(reader.finish());
    state.unresolved_attempts.push_back(attempt);
  }

  if (index != records.size()) {
    return Error(ErrorCode::CountMismatch, "records remain after the declared tables were read")
        .with_subject(records[index].name());
  }

  // The decoded body must be structurally valid, and its canonical form must be a
  // fixed point: re-encoding what was just decoded has to reproduce the identical
  // bytes, or the file is not the canonical spelling of the state it describes.
  CFM_TRYV(validate_structure(state));
  const std::string reencoded = encode_state(state);
  if (reencoded != text) {
    return Error(ErrorCode::MalformedRecord,
                 "the decoded state does not re-encode to the bytes it was decoded from")
        .with_subject("canonical fixed point");
  }
  return state;
}

}  // namespace dccp::cooling_failure_manager
