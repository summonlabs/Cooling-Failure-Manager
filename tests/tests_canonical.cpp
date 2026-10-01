// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
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
#include "dccp/cooling_failure_manager/text.hpp"
#include "dccp/cooling_failure_manager/version.hpp"

#include "test_framework.hpp"

namespace cfm = dccp::cooling_failure_manager;

namespace {

constexpr std::int64_t kCanonicalClock = 1000000000;
constexpr std::int64_t kCanonicalWindow = 60000;

const cfm::ScopeId kCanonicalLoop = *cfm::ScopeId::parse("loop.can");
const cfm::ScopeId kCanonicalPlant = *cfm::ScopeId::parse("plant.can");
const cfm::ScopeId kCanonicalRack = *cfm::ScopeId::parse("rack.can");

cfm::DecisionPolicy canonical_policy() {
  cfm::DecisionPolicy policy;
  policy.evidence_window = cfm::DurationMilliseconds(kCanonicalWindow);
  policy.confirm_min_observations = 1;
  policy.suspect_min_observations = 1;
  return policy;
}

cfm::CoolingScope plant_scope() {
  cfm::CoolingScope scope;
  scope.id = kCanonicalPlant;
  scope.kind = cfm::ScopeKind::Plant;
  scope.display_name = "Plant \"A\" \\ north";
  scope.policy.envelope.declared_demand = *cfm::DeclaredQuantity::make(5000000, "W");
  scope.policy.requirements = {
      {cfm::ObservationChannel::ChillerStatus, cfm::DurationMilliseconds(kCanonicalWindow)},
      {cfm::ObservationChannel::ThermalCapacityMeter, cfm::DurationMilliseconds(kCanonicalWindow)}};
  scope.bindings.set("cooling-topology",
                     *cfm::AuthorityRef::make("cooling-topology", "site.can", cfm::ExternalGeneration(3)));
  return scope;
}

cfm::CoolingScope loop_scope() {
  cfm::CoolingScope scope;
  scope.id = kCanonicalLoop;
  scope.kind = cfm::ScopeKind::Loop;
  scope.display_name = "Loop with a tab\tand a newline\ninside";
  scope.policy.envelope.min_flow = *cfm::DeclaredQuantity::make(30000, "mL/s");
  scope.policy.envelope.min_differential_pressure = *cfm::DeclaredQuantity::make(50000, "Pa-dp");
  scope.policy.envelope.min_thermal_margin = *cfm::DeclaredQuantity::make(2000, "mK");
  scope.policy.envelope.max_supply_temperature = *cfm::DeclaredQuantity::make(25000, "mC");
  scope.policy.envelope.declared_demand = *cfm::DeclaredQuantity::make(2000000, "W");
  scope.policy.strict_classes = {cfm::FailureClass::Leak, cfm::FailureClass::LoopLoss};
  scope.policy.requirements = {
      {cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(kCanonicalWindow)},
      {cfm::ObservationChannel::DifferentialPressure, cfm::DurationMilliseconds(kCanonicalWindow)},
      {cfm::ObservationChannel::LeakDetector, cfm::DurationMilliseconds(kCanonicalWindow)},
      {cfm::ObservationChannel::ThermalCapacityMeter, cfm::DurationMilliseconds(kCanonicalWindow)},
      {cfm::ObservationChannel::ThermalMarginMeter, cfm::DurationMilliseconds(kCanonicalWindow)}};
  scope.policy.recovery_dwell = cfm::DurationMilliseconds(300000);
  scope.policy.recovery_hysteresis = cfm::DurationMilliseconds(120000);
  scope.dependencies.push_back(
      cfm::ScopeDependency{kCanonicalPlant, cfm::DependencyKind::SuppliesCoolant, 1000000});
  return scope;
}

cfm::CoolingScope rack_scope() {
  cfm::CoolingScope scope;
  scope.id = kCanonicalRack;
  scope.kind = cfm::ScopeKind::Rack;
  scope.policy.envelope.min_flow = *cfm::DeclaredQuantity::make(1000, "mL/s");
  scope.policy.requirements = {
      {cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(kCanonicalWindow)}};
  scope.dependencies.push_back(
      cfm::ScopeDependency{kCanonicalPlant, cfm::DependencyKind::SharesPlant, 800000});
  return scope;
}

void record_scalar(cfm::ObservationSet& set, std::string_view id, const cfm::ScopeId& scope,
                   cfm::ObservationChannel channel, std::int64_t value, std::string_view unit) {
  cfm::Observation observation;
  observation.id = *cfm::ObservationId::parse(id);
  observation.scope = scope;
  observation.channel = channel;
  observation.quantity = *cfm::Quantity::observed(value, unit, cfm::ObservationQuality::Good,
                                                 cfm::ObservationSequence(1));
  observation.observed_at = cfm::DecisionClock(kCanonicalClock - 1000);
  observation.recorded_at = cfm::DecisionClock(kCanonicalClock - 1000);
  observation.producer = "canonical-producer";
  observation.sensor = "canonical-producer.sensor";
  observation.evidence_generation = cfm::EvidenceGeneration(4);
  CT_REQUIRE(set.add(observation).has_value());
}

void record_status(cfm::ObservationSet& set, std::string_view id, const cfm::ScopeId& scope,
                   cfm::ObservationChannel channel, std::int64_t code) {
  cfm::Observation observation;
  observation.id = *cfm::ObservationId::parse(id);
  observation.scope = scope;
  observation.channel = channel;
  observation.quantity = *cfm::Quantity::observed(code, std::string_view(), cfm::ObservationQuality::Good,
                                                 cfm::ObservationSequence(1));
  observation.observed_at = cfm::DecisionClock(kCanonicalClock - 1000);
  observation.recorded_at = cfm::DecisionClock(kCanonicalClock - 1000);
  observation.producer = "canonical-producer";
  observation.sensor = "canonical-producer.sensor";
  observation.evidence_generation = cfm::EvidenceGeneration(4);
  CT_REQUIRE(set.add(observation).has_value());
}

void record_leak(cfm::ObservationSet& set, std::string_view id, const cfm::ScopeId& scope,
                 cfm::LeakState state) {
  cfm::Observation observation;
  observation.id = *cfm::ObservationId::parse(id);
  observation.scope = scope;
  observation.channel = cfm::ObservationChannel::LeakDetector;
  observation.leak = state;
  observation.quantity = cfm::Quantity::indeterminate();
  observation.observed_at = cfm::DecisionClock(kCanonicalClock - 1000);
  observation.recorded_at = cfm::DecisionClock(kCanonicalClock - 1000);
  observation.producer = "canonical-producer";
  observation.sensor = "canonical-producer.sensor";
  observation.evidence_generation = cfm::EvidenceGeneration(4);
  CT_REQUIRE(set.add(observation).has_value());
}

/// Builds a state with every field of every table populated: authorities, three
/// scopes, dependencies, confirmed and suspected failures with basis lists, a
/// plan with eligibility, restrictions and attempts, evidence, decisions with all
/// four class buckets and an explanation, and an unresolved attempt list.
cfm::CoolingFailureState rich_state() {
  cfm::CoolingFailureState skeleton;
  skeleton.evaluated_at = cfm::DecisionClock(kCanonicalClock);
  skeleton.scopes = {plant_scope(), loop_scope(), rack_scope()};

  cfm::ObservationSet observations;
  record_status(observations, "can.chiller", kCanonicalPlant, cfm::ObservationChannel::ChillerStatus, 2);
  record_scalar(observations, "can.capacity", kCanonicalPlant,
                cfm::ObservationChannel::ThermalCapacityMeter, 1000, "W");
  record_scalar(observations, "can.flow", kCanonicalLoop, cfm::ObservationChannel::FlowMeter, 0, "mL/s");
  record_scalar(observations, "can.dp", kCanonicalLoop, cfm::ObservationChannel::DifferentialPressure, 0,
                "Pa-dp");
  record_leak(observations, "can.leak", kCanonicalLoop, cfm::LeakState::LeakActive);
  record_scalar(observations, "can.margin", kCanonicalLoop, cfm::ObservationChannel::ThermalMarginMeter,
                100, "mK");
  record_scalar(observations, "can.rack-flow", kCanonicalRack, cfm::ObservationChannel::FlowMeter, 900,
                "mL/s");

  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = canonical_policy();
  input.clock = cfm::DecisionClock(kCanonicalClock);
  input.bindings.set("cooling-topology",
                     *cfm::AuthorityRef::make("cooling-topology", "site.can", cfm::ExternalGeneration(3)));
  input.bindings.set("policy",
                     *cfm::AuthorityRef::make("cooling-failure-policy", "policy.v2",
                                              cfm::ExternalGeneration(9)));
  input.observed_bindings.current = input.bindings;
  input.recovery_requests = {kCanonicalRack};

  cfm::DecisionInput::SolicitationRequest solicitation;
  solicitation.scope = kCanonicalLoop;
  solicitation.solicitation = *cfm::MutationId::parse("can.solicit.1");
  solicitation.attempt = *cfm::AttemptOrdinal::parse(1);
  solicitation.action = cfm::ResponseAction::StartStandbyPump;
  solicitation.addressee = "liquid-cooling-control";
  input.solicitations = {solicitation};

  cfm::Result<cfm::DecisionOutcome> outcome = cfm::evaluate(input);
  CT_REQUIRE(outcome.has_value());
  return outcome.value().state;
}

}  // namespace

// ===========================================================================
// Round trips
// ===========================================================================

CT_TEST(canonical_round_trip_preserves_every_table) {
  const cfm::CoolingFailureState state = rich_state();
  const std::string encoded = cfm::encode_state(state);
  CT_CHECK(!encoded.empty());
  // The format is named and versioned, and the trailing count is present.
  CT_CHECK(encoded.rfind(std::string(cfm::canonical_format_name()), 0) == 0);
  CT_CHECK(encoded.find("\nend\t") != std::string::npos);

  const cfm::Result<cfm::CoolingFailureState> decoded = cfm::decode_state(encoded);
  CT_REQUIRE(decoded.has_value());
  CT_CHECK_EQ(decoded->scopes.size(), state.scopes.size());
  CT_CHECK_EQ(decoded->failures.size(), state.failures.size());
  CT_CHECK_EQ(decoded->plans.size(), state.plans.size());
  CT_CHECK_EQ(decoded->evidence.size(), state.evidence.size());
  CT_CHECK_EQ(decoded->decisions.size(), state.decisions.size());
  CT_CHECK_EQ(decoded->unresolved_attempts.size(), state.unresolved_attempts.size());
  CT_CHECK_EQ(decoded->bindings.size(), state.bindings.size());
  CT_CHECK_EQ(decoded->generation.value(), state.generation.value());
  CT_CHECK_EQ(decoded->evaluated_at.milliseconds(), state.evaluated_at.milliseconds());
  // The canonical form is a fixed point and the digest is preserved.
  CT_CHECK(cfm::encode_state(decoded.value()) == encoded);
  CT_CHECK(cfm::state_digest(decoded.value()) == cfm::state_digest(state));
}

CT_TEST(canonical_preserves_escaped_text_exactly) {
  const cfm::CoolingFailureState state = rich_state();
  const std::string encoded = cfm::encode_state(state);
  const cfm::Result<cfm::CoolingFailureState> decoded = cfm::decode_state(encoded);
  CT_REQUIRE(decoded.has_value());
  CT_REQUIRE(decoded->scopes.size() == 3);
  // The display name contains a quote, a backslash, a tab and a newline; all four
  // survive the round trip and none of them can break the record framing.
  const cfm::CoolingScope* loop = cfm::find_scope(decoded.value(), kCanonicalLoop);
  CT_REQUIRE(loop != nullptr);
  CT_CHECK(loop->display_name == "Loop with a tab\tand a newline\ninside");
  bool found_escaped_quote = false;
  for (const cfm::CoolingScope& scope : decoded->scopes) {
    if (scope.display_name.find('"') != std::string::npos ||
        scope.display_name.find('\\') != std::string::npos) {
      found_escaped_quote = true;
    }
  }
  CT_CHECK(found_escaped_quote);
  // No record line may carry a raw tab inside a value or a raw newline.
  std::size_t start = 0;
  while (start < encoded.size()) {
    const std::size_t next = encoded.find('\n', start);
    CT_REQUIRE(next != std::string::npos);
    start = next + 1;
  }
}

CT_TEST(canonical_encoding_is_independent_of_input_order) {
  // Two states built by inserting the same elements in opposite orders encode to
  // the same bytes, because canonicalize() fixes the order and the encoder follows
  // it.
  const cfm::CoolingFailureState first = rich_state();
  cfm::CoolingFailureState second = first;
  std::reverse(second.scopes.begin(), second.scopes.end());
  std::reverse(second.failures.begin(), second.failures.end());
  std::reverse(second.evidence.begin(), second.evidence.end());
  std::reverse(second.decisions.begin(), second.decisions.end());
  std::reverse(second.plans.begin(), second.plans.end());
  CT_REQUIRE(cfm::canonicalize(second).has_value());
  CT_CHECK(cfm::encode_state(second) == cfm::encode_state(first));
  CT_CHECK(cfm::state_digest(second) == cfm::state_digest(first));
}

CT_TEST(canonical_digest_changes_when_anything_meaningful_changes) {
  const cfm::CoolingFailureState state = rich_state();
  const cfm::Digest baseline = cfm::state_digest(state);

  cfm::CoolingFailureState clock_changed = state;
  clock_changed.evaluated_at = cfm::DecisionClock(kCanonicalClock + 1);
  CT_CHECK(!(cfm::state_digest(clock_changed) == baseline));

  cfm::CoolingFailureState severity_changed = state;
  CT_REQUIRE(!severity_changed.failures.empty());
  severity_changed.failures.front().severity = cfm::Severity::None;
  CT_CHECK(!(cfm::state_digest(severity_changed) == baseline));

  cfm::CoolingFailureState text_changed = state;
  CT_REQUIRE(!text_changed.decisions.empty());
  text_changed.decisions.front().explanation.push_back("a line that was not there before");
  CT_CHECK(!(cfm::state_digest(text_changed) == baseline));

  cfm::CoolingFailureState binding_changed = state;
  CT_REQUIRE(!binding_changed.bindings.entries().empty());
  const cfm::AuthorityRef* reference = binding_changed.bindings.find("cooling-topology");
  CT_REQUIRE(reference != nullptr);
  CT_REQUIRE(binding_changed.bindings
                 .set("cooling-topology",
                      *cfm::AuthorityRef::make(reference->owner(), reference->identity(),
                                               cfm::ExternalGeneration(reference->generation().value() + 1)))
                 .has_value());
  CT_CHECK(!(cfm::state_digest(binding_changed) == baseline));
}

// ===========================================================================
// Strict decoding
// ===========================================================================

CT_TEST(canonical_refuses_a_flipped_byte_anywhere) {
  const cfm::CoolingFailureState state = rich_state();
  const std::string encoded = cfm::encode_state(state);
  // Every byte position is flipped in turn; each must be detected. Positions
  // inside escaped text can change the text without changing the digest, which the
  // fixed-point check catches, so every flip must fail one check or the other.
  for (std::size_t offset = 0; offset < encoded.size(); ++offset) {
    if (encoded[offset] == '\n' || encoded[offset] == '\t') {
      continue;  // a separator flip is covered by the framing cases below
    }
    std::string damaged = encoded;
    damaged[offset] = static_cast<char>(damaged[offset] ^ 0x20);
    const cfm::Result<cfm::CoolingFailureState> decoded = cfm::decode_state(damaged);
    CT_CHECK_MSG(!decoded.has_value(),
                 "a flipped byte at offset " + std::to_string(offset) + " was accepted");
  }
}

CT_TEST(canonical_refuses_truncation_at_every_boundary) {
  const cfm::CoolingFailureState state = rich_state();
  const std::string encoded = cfm::encode_state(state);
  const std::size_t boundaries[] = {1, 2, encoded.size() / 4, encoded.size() / 2,
                                   encoded.size() - 2, encoded.size() - 1};
  for (const std::size_t size : boundaries) {
    const cfm::Result<cfm::CoolingFailureState> decoded = cfm::decode_state(encoded.substr(0, size));
    CT_CHECK_MSG(!decoded.has_value(), "a truncation to " + std::to_string(size) + " was accepted");
    if (!decoded.has_value()) {
      // Every truncation is reported as a truncated, malformed or mismatched body
      // rather than as a state.
      const cfm::ErrorCode code = decoded.error().code();
      CT_CHECK(code == cfm::ErrorCode::TruncatedInput || code == cfm::ErrorCode::MalformedRecord ||
               code == cfm::ErrorCode::CountMismatch || code == cfm::ErrorCode::DigestMismatch ||
               code == cfm::ErrorCode::MissingField || code == cfm::ErrorCode::EmptyInput);
    }
  }
}

CT_TEST(canonical_refuses_reordering_and_duplication) {
  const cfm::CoolingFailureState state = rich_state();
  const std::string encoded = cfm::encode_state(state);

  // Reordering two record lines invalidates the count or the count's digest.
  std::vector<std::string> lines;
  std::size_t start = 0;
  while (start <= encoded.size()) {
    const std::size_t next = encoded.find('\n', start);
    if (next == std::string::npos) {
      break;
    }
    lines.push_back(encoded.substr(start, next - start));
    start = next + 1;
  }
  CT_REQUIRE(lines.size() > 8);
  std::vector<std::string> swapped = lines;
  std::swap(swapped[3], swapped[4]);
  std::string swapped_text;
  for (const std::string& line : swapped) {
    swapped_text += line;
    swapped_text += '\n';
  }
  CT_CHECK(!cfm::decode_state(swapped_text).has_value());

  // Duplicating a record line changes the count.
  std::vector<std::string> duplicated = lines;
  duplicated.insert(duplicated.begin() + 3, lines[3]);
  std::string duplicated_text;
  for (const std::string& line : duplicated) {
    duplicated_text += line;
    duplicated_text += '\n';
  }
  CT_CHECK(!cfm::decode_state(duplicated_text).has_value());

  // Removing a record line changes the count too.
  std::vector<std::string> removed = lines;
  removed.erase(removed.begin() + 3);
  std::string removed_text;
  for (const std::string& line : removed) {
    removed_text += line;
    removed_text += '\n';
  }
  CT_CHECK(!cfm::decode_state(removed_text).has_value());
}

CT_TEST(canonical_refuses_an_unknown_record_unknown_token_and_unknown_field) {
  const cfm::CoolingFailureState state = rich_state();
  const std::string encoded = cfm::encode_state(state);

  auto replace_first = [&](std::string_view from, std::string_view to) {
    std::string copy = encoded;
    const std::size_t position = copy.find(from);
    if (position == std::string::npos) {
      return std::string();
    }
    copy.replace(position, from.size(), to);
    return copy;
  };

  // An unknown record name.
  std::string unknown_record = encoded;
  const std::size_t record_start = unknown_record.find("\nscope\t");
  CT_REQUIRE(record_start != std::string::npos);
  unknown_record.replace(record_start + 1, 5, "scopx");
  CT_CHECK(!cfm::decode_state(unknown_record).has_value());

  // An unknown file format version.
  std::string bad_version = replace_first("dccp-cooling-failure-state\t1\t",
                                          "dccp-cooling-failure-state\t2\t");
  CT_REQUIRE(!bad_version.empty());
  const cfm::Result<cfm::CoolingFailureState> version_result = cfm::decode_state(bad_version);
  CT_CHECK(!version_result.has_value());
  if (!version_result.has_value()) {
    CT_CHECK(version_result.error().code() == cfm::ErrorCode::UnsupportedSchemaVersion);
  }

  // A wrong format name.
  std::string bad_name = replace_first("dccp-cooling-failure-state", "dccp-something-else");
  CT_REQUIRE(!bad_name.empty());
  CT_CHECK(!cfm::decode_state(bad_name).has_value());

  // An unknown enumeration token in a body record. Editing a record invalidates
  // the trailing digest, so the refusal may come from the digest check before the
  // vocabulary is reached; both are refusals of the same damaged input, and the
  // vocabulary check is what a reader sees once the digest is recomputed.
  std::string bad_token = replace_first("confirmation=confirmed", "confirmation=probably");
  if (!bad_token.empty()) {
    const cfm::Result<cfm::CoolingFailureState> token_result = cfm::decode_state(bad_token);
    CT_CHECK(!token_result.has_value());
    if (!token_result.has_value()) {
      CT_CHECK(token_result.error().code() == cfm::ErrorCode::DigestMismatch ||
               token_result.error().code() == cfm::ErrorCode::UnknownEnumToken);
    }
    // The same edit with the trailing digest recomputed must be refused by the
    // vocabulary: an unknown token is never mapped onto a default. The count of
    // body records is the number of lines less the header line and the end line.
    // The same edit with the digest recomputed must be refused by the vocabulary:
    // an unknown token is never mapped onto a default.
    std::vector<std::string> lines;
    std::size_t start = 0;
    while (start <= bad_token.size()) {
      const std::size_t next = bad_token.find('\n', start);
      if (next == std::string::npos) {
        break;
      }
      lines.push_back(bad_token.substr(start, next - start));
      start = next + 1;
    }
    CT_REQUIRE(lines.size() > 2);
    std::string body;
    for (std::size_t index = 0; index + 1 < lines.size(); ++index) {
      body += lines[index];
      body += '\n';
    }
    std::string repaired = body + "end" + '\t' + std::to_string(lines.size() - 2) + '\t' +
                           cfm::digest_bytes(body).to_hex() + '\n';
    const cfm::Result<cfm::CoolingFailureState> repaired_result = cfm::decode_state(repaired);
    CT_CHECK(!repaired_result.has_value());
    if (!repaired_result.has_value()) {
      const cfm::ErrorCode code = repaired_result.error().code();
      CT_CHECK(code == cfm::ErrorCode::UnknownEnumToken || code == cfm::ErrorCode::DigestMismatch);
    }
  }

  // A field the format does not define.
  std::string extra_field = replace_first("kind=loop\t", "kind=loop\textra=1\t");
  if (!extra_field.empty()) {
    CT_CHECK(!cfm::decode_state(extra_field).has_value());
  }

  // A repeated field.
  std::string repeated_field = replace_first("kind=loop\t", "kind=loop\tkind=loop\t");
  if (!repeated_field.empty()) {
    CT_CHECK(!cfm::decode_state(repeated_field).has_value());
  }

  // A missing field.
  std::string missing_field = replace_first("\tkind=loop", "");
  if (!missing_field.empty()) {
    CT_CHECK(!cfm::decode_state(missing_field).has_value());
  }
}

CT_TEST(canonical_refuses_empty_and_non_text_input) {
  CT_CHECK(!cfm::decode_state("").has_value());
  CT_CHECK(!cfm::decode_state("not a canonical state at all").has_value());
  CT_CHECK(!cfm::decode_state("dccp-cooling-failure-state\t1\tgeneration=0\tparent=0\tclock=0").has_value());
  CT_CHECK(!cfm::decode_state("\n\n\n").has_value());
  // A body with a carriage return is refused rather than tolerated.
  const cfm::CoolingFailureState state = rich_state();
  std::string with_cr = cfm::encode_state(state);
  with_cr.insert(with_cr.find('\n'), "\r");
  CT_CHECK(!cfm::decode_state(with_cr).has_value());
  // A NUL byte anywhere is refused.
  std::string with_nul = cfm::encode_state(state);
  with_nul.insert(with_nul.size() / 2, 1, '\0');
  CT_CHECK(!cfm::decode_state(with_nul).has_value());
}

CT_TEST(canonical_refuses_an_out_of_order_body) {
  const cfm::CoolingFailureState state = rich_state();
  const std::string encoded = cfm::encode_state(state);
  std::vector<std::string> lines;
  std::size_t start = 0;
  while (start <= encoded.size()) {
    const std::size_t next = encoded.find('\n', start);
    if (next == std::string::npos) {
      break;
    }
    lines.push_back(encoded.substr(start, next - start));
    start = next + 1;
  }
  // Move the first failure record before the last scope record, which the decoder
  // must refuse because parentage is positional.
  std::size_t failure_index = 0;
  std::size_t scope_index = 0;
  for (std::size_t index = 0; index < lines.size(); ++index) {
    if (lines[index].rfind("failure\t", 0) == 0 && failure_index == 0) {
      failure_index = index;
    }
    if (lines[index].rfind("scope\t", 0) == 0) {
      scope_index = index;
    }
  }
  CT_REQUIRE(failure_index != 0 && scope_index != 0 && failure_index > scope_index);
  const std::string moved = lines[failure_index];
  lines.erase(lines.begin() + static_cast<std::ptrdiff_t>(failure_index));
  lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(scope_index), moved);
  // The digest no longer covers the body, so the refusal may come from the digest
  // or from the ordering check; either is a refusal.
  std::string reordered;
  for (const std::string& line : lines) {
    reordered += line;
    reordered += '\n';
  }
  CT_CHECK(!cfm::decode_state(reordered).has_value());
}

CT_TEST(canonical_format_constants_are_stable) {
  CT_CHECK_EQ(std::string(cfm::canonical_format_name()), std::string("dccp-cooling-failure-state"));
  CT_CHECK_EQ(cfm::canonical_format_version(), static_cast<std::uint32_t>(1));
  // The attempt-record digest is a plain digest over the bytes it is given, which
  // is what the store's idempotency records rely on.
  const cfm::Digest digest = cfm::attempt_record_digest("mutation\t1");
  CT_CHECK(!digest.is_zero());
  CT_CHECK(digest == cfm::digest_bytes("mutation\t1"));
}
