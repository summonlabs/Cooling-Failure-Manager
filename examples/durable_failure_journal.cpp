// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// A durable cooling-failure journal.
//
// The example publishes three decisions to a real store directory, then reopens
// the store from a second handle and reads the head back. It shows the parts of
// the durability contract a caller depends on: the generation chain, the
// integrity digest of the state of record, the commit sequence, and the fact
// that reading the head re-verifies the payload instead of trusting a cache.
//
// Everything here is SYNTHETIC except the store, whose files, lock and durability
// ordering are the operating system's own.
//
// usage: durable_failure_journal <store-directory>

#include "example_support.hpp"

using example::check;
using example::note;
using example::must_quantity;
using example::must_scope;
using example::record;
using example::Journal;

int main(int argc, char** argv) {
  if (argc < 2) {
    std::printf("usage: durable_failure_journal <store-directory>\n");
    return 2;
  }
  const std::string root = argv[1];

  const cfm::ScopeId loop = must_scope("loop.journal");
  cfm::CoolingScope scope;
  scope.id = loop;
  scope.kind = cfm::ScopeKind::Loop;
  scope.policy.envelope.min_flow = must_quantity(5000, "mL/s");
  scope.policy.requirements.push_back(
      cfm::EvidenceRequirement{cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(30000)});

  cfm::DecisionPolicy policy;
  policy.evidence_window = cfm::DurationMilliseconds(30000);

  const std::int64_t flow_values[3] = {9000, 4500, 0};
  const std::int64_t clocks[3] = {1000, 2000, 3000};

  cfm::Result<Journal> journal = Journal::create(root);
  check(journal.has_value(), "the store was created");
  if (!journal.has_value()) {
    std::printf("error: %s\n", journal.error().to_string().c_str());
    return 1;
  }

  cfm::CoolingFailureState carried;
  carried.evaluated_at = cfm::DecisionClock(0);
  carried.scopes = {scope};

  for (std::size_t step = 0; step < 3; ++step) {
    cfm::ObservationSet observations;
    record(observations, "obs.flow." + std::to_string(step), loop, cfm::ObservationChannel::FlowMeter,
           flow_values[step], "mL/s", clocks[step], "loop-flow");
    cfm::DecisionInput input;
    input.prior = &carried;
    input.observations = &observations;
    input.policy = policy;
    input.clock = cfm::DecisionClock(clocks[step]);
    cfm::Result<cfm::DecisionOutcome> outcome = cfm::evaluate(input);
    check(outcome.has_value(), "the evaluation succeeded");
    if (!outcome.has_value()) {
      std::printf("error: %s\n", outcome.error().to_string().c_str());
      return 1;
    }
    cfm::Result<cfm::PublicationReceipt> receipt =
        journal->append(outcome->state, "example.journal.step" + std::to_string(step), 1);
    check(receipt.has_value(), "the decision was published");
    if (!receipt.has_value()) {
      std::printf("error: %s\n", receipt.error().to_string().c_str());
      return 1;
    }
    check(receipt->generation.value() == step + 1, "generations are assigned in order");
    note("published generation " + std::to_string(receipt->generation.value()) + " digest " +
         receipt->digest.to_hex().substr(0, 16) + " durability " +
         std::string(cfm::to_token(receipt->durability)));
    carried = outcome->state;
  }

  // A retry of an already committed attempt replays instead of publishing twice.
  cfm::Result<cfm::PublicationReceipt> replay =
      journal->append(carried, "example.journal.step2", 1);
  check(replay.has_value(), "a retry of a committed attempt replays");
  if (replay.has_value()) {
    check(replay->replayed, "the retry is reported as a replay");
    check(replay->generation.value() == 3, "the replay names the original generation");
    note("replay: generation " + std::to_string(replay->generation.value()) + " replayed=true");
  }

  cfm::Result<std::vector<cfm::HistoryEntry>> history = journal->history();
  check(history.has_value(), "history is readable");
  if (history.has_value()) {
    check(history->size() == 3, "three generations are retained");
    note("history entries " + std::to_string(history->size()));
  }

  cfm::Result<void> closed = journal->close();
  check(closed.has_value(), "the writing handle closed");

  cfm::Result<Journal> reopened = Journal::open(root);
  check(reopened.has_value(), "a second handle reopens the store");
  if (!reopened.has_value()) {
    std::printf("error: %s\n", reopened.error().to_string().c_str());
    return 1;
  }
  cfm::Result<cfm::CoolingFailureState> head = reopened->head();
  check(head.has_value(), "the head is readable");
  if (head.has_value()) {
    check(head->generation.value() == 3, "the head is the newest generation");
    check(cfm::state_digest(head.value()) == cfm::state_digest(carried),
          "the head digest matches the state that was published");
    const cfm::ScopeDecision* decision = cfm::find_decision(head.value(), loop);
    check(decision != nullptr, "the decision survived the restart");
    if (decision != nullptr) {
      check(std::find(decision->confirmed_classes.begin(), decision->confirmed_classes.end(),
                      cfm::FailureClass::LoopLoss) != decision->confirmed_classes.end(),
            "the confirmed loop loss is part of the state of record");
    }
  }
  cfm::Result<cfm::VerifyReport> report = reopened->verify();
  check(report.has_value() && report->ok(), "verification accepts every retained generation");
  if (report.has_value()) {
    note("verify: head=" + std::to_string(report->head.value()) + " verified=" +
         std::to_string(report->generations_verified) + " canonical-fixed-point=" +
         (report->canonical_fixed_point_verified ? "yes" : "no"));
  }

  if (example::failures == 0) {
    std::printf("example durable_failure_journal ok\n");
    return 0;
  }
  std::printf("example durable_failure_journal FAILED: %d check(s)\n", example::failures);
  return 1;
}
