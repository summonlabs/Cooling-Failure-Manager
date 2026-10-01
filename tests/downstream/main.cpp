// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Downstream consumer of the installed package.
//
// This program exists to prove that an independent project can find, link and
// use the installed artifact: it includes only the installed public headers,
// links only the exported target, and exercises the parts of the contract a
// consumer actually depends on - version agreement, a deterministic
// classification, a canonical round trip, and a durable publication that is
// re-read and verified through the installed library.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include "dccp/cooling_failure_manager/canonical.hpp"
#include "dccp/cooling_failure_manager/decision.hpp"
#include "dccp/cooling_failure_manager/evidence.hpp"
#include "dccp/cooling_failure_manager/store.hpp"
#include "dccp/cooling_failure_manager/version.hpp"

namespace cfm = dccp::cooling_failure_manager;

namespace {

int failures = 0;

void check(bool condition, const char* what) {
  if (!condition) {
    std::printf("FAIL %s\n", what);
    ++failures;
  }
}

cfm::Result<cfm::ScopeId> scope_id(std::string_view text) { return cfm::ScopeId::parse(text); }

}  // namespace

int main(int argc, char** argv) {
  // 1. The installed headers and the installed library agree on the version, and
  //    the consumer's own compile-time expectation of the ABI major matches.
  const std::string version(cfm::version_string());
  check(version == "1.0.1", "version_string is 1.0.1");
  check(cfm::kVersionMajor == 1 && cfm::kVersionMinor == 0 && cfm::kVersionPatch == 1,
        "compiled-in version components");
  check(!cfm::systems_boundary().empty(), "systems boundary is documented");

  // 2. A minimal synthetic scope with declared bounds classifies a dead flow as a
  //    confirmed loop loss, and classifies silence as unsupported rather than
  //    healthy. Both are the contract a consumer builds on.
  cfm::CoolingScope scope;
  cfm::Result<cfm::ScopeId> id = scope_id("loop.a");
  if (!id.has_value()) {
    std::printf("FAIL scope id parse: %s\n", id.error().to_string().c_str());
    return 1;
  }
  scope.id = id.value();
  scope.kind = cfm::ScopeKind::Loop;
  cfm::Result<cfm::DeclaredQuantity> floor = cfm::DeclaredQuantity::make(1000, "mL/s");
  if (!floor.has_value()) {
    std::printf("FAIL declared quantity: %s\n", floor.error().to_string().c_str());
    return 1;
  }
  scope.policy.envelope.min_flow = floor.value();
  scope.policy.requirements.push_back(
      cfm::EvidenceRequirement{cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(60000)});

  cfm::DecisionPolicy policy;
  policy.evidence_window = cfm::DurationMilliseconds(60000);

  cfm::ObservationSet observations;
  cfm::Result<cfm::Quantity> dead_flow =
      cfm::Quantity::observed(0, "mL/s", cfm::ObservationQuality::Good, cfm::ObservationSequence(1));
  if (!dead_flow.has_value()) {
    std::printf("FAIL quantity: %s\n", dead_flow.error().to_string().c_str());
    return 1;
  }
  cfm::Observation observation;
  cfm::Result<cfm::ObservationId> observation_id = cfm::ObservationId::parse("obs.1");
  if (!observation_id.has_value()) {
    return 1;
  }
  observation.id = observation_id.value();
  observation.scope = scope.id;
  observation.channel = cfm::ObservationChannel::FlowMeter;
  observation.quantity = dead_flow.value();
  observation.observed_at = cfm::DecisionClock(1000);
  observation.recorded_at = cfm::DecisionClock(1001);
  observation.producer = "bench-flow";
  observation.sensor = "fm-1";
  observation.evidence_generation = cfm::EvidenceGeneration(7);
  cfm::Result<void> added = observations.add(observation);
  check(added.has_value(), "observation recorded");

  cfm::CoolingFailureState skeleton;
  skeleton.evaluated_at = cfm::DecisionClock(1000);
  skeleton.scopes.push_back(scope);

  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = policy;
  input.clock = cfm::DecisionClock(1000);

  cfm::Result<cfm::DecisionOutcome> outcome = cfm::evaluate(input);
  check(outcome.has_value(), "evaluation succeeds");
  if (outcome.has_value()) {
    check(outcome->state.decisions.size() == 1, "one decision is produced");
    if (!outcome->state.decisions.empty()) {
      const cfm::ScopeDecision& decision = outcome->state.decisions.front();
      check(std::find(decision.confirmed_classes.begin(), decision.confirmed_classes.end(),
                      cfm::FailureClass::LoopLoss) != decision.confirmed_classes.end(),
            "a dead flow confirms a loop loss");
      check(decision.severity != cfm::Severity::None, "a confirmed loss carries a severity");
    }
    // 3. The canonical encoding is a fixed point and survives a decode.
    const std::string encoded = cfm::encode_state(outcome->state);
    check(!encoded.empty(), "canonical encoding is non-empty");
    cfm::Result<cfm::CoolingFailureState> decoded = cfm::decode_state(encoded);
    check(decoded.has_value(), "canonical decoding succeeds");
    if (decoded.has_value()) {
      check(cfm::encode_state(decoded.value()) == encoded, "canonical encoding is a fixed point");
      check(cfm::state_digest(decoded.value()) == cfm::state_digest(outcome->state),
            "a round trip preserves the digest");
    }
  }

  // 4. A durable publication through the installed library, then a read-back from
  //    a second handle. The consumer never includes an internal header.
  if (argc > 1) {
    cfm::StoreOptions options;
    options.root = argv[1];
    cfm::Result<cfm::StoreId> store_id = cfm::StoreId::parse("downstream.store");
    if (!store_id.has_value()) {
      return 1;
    }
    cfm::Result<cfm::Store> created = cfm::Store::create(options, store_id.value());
    if (!created.has_value()) {
      std::printf("FAIL store create: %s\n", created.error().to_string().c_str());
      return 1;
    }
    cfm::PublicationRequest request;
    cfm::Result<cfm::MutationId> mutation = cfm::MutationId::parse("downstream.publish");
    if (!mutation.has_value()) {
      return 1;
    }
    request.mutation = mutation.value();
    cfm::Result<cfm::AttemptOrdinal> ordinal = cfm::AttemptOrdinal::parse(1);
    if (!ordinal.has_value()) {
      return 1;
    }
    request.attempt = ordinal.value();
    request.body = outcome.has_value() ? outcome->state : cfm::CoolingFailureState{};
    cfm::Result<cfm::PublicationReceipt> receipt = created->publish(request);
    check(receipt.has_value(), "publication succeeds");
    if (receipt.has_value()) {
      check(receipt->generation.value() == 1, "the first publication is generation 1");
      check(receipt->durability == cfm::PublicationDurability::Durable, "durability was established");
      cfm::Result<void> closed = created->close();
      check(closed.has_value(), "store closes");
      cfm::StoreOptions read_options;
      read_options.root = argv[1];
      read_options.mode = cfm::StoreMode::ReadOnly;
      cfm::Result<cfm::Store> reopened = cfm::Store::open(read_options);
      check(reopened.has_value(), "a read-only handle reopens the store");
      if (reopened.has_value()) {
        cfm::Result<cfm::CoolingFailureState> head = reopened->head();
        check(head.has_value(), "the head is readable and verified");
        if (head.has_value()) {
          check(head->generation.value() == 1, "the head is the published generation");
          check(cfm::state_digest(head.value()) == cfm::state_digest(request.body),
                "the head digest matches what was published");
        }
        cfm::Result<cfm::VerifyReport> report = reopened->verify(cfm::VerifyOptions{});
        check(report.has_value() && report->ok(), "verification accepts the store");
      }
    }
  }

  if (failures == 0) {
    std::printf("downstream consumer ok: version=%s head-verified storage=verified\n", version.c_str());
    return 0;
  }
  std::printf("downstream consumer FAILED: %d check(s)\n", failures);
  return 1;
}
