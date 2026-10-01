// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// A restart with a response in flight: never redispatch, always reconcile.
//
// The example publishes a decision with a solicited, unacknowledged attempt, then
// hands the store to a successor handle that holds a new epoch and incarnation.
// The successor evaluates with authority_changed set, which adopts the in-flight
// attempt as Unresolved instead of pretending it succeeded or silently retrying
// it. From there the attempt is resolved by an explicit publication, and the store
// refuses a fresh publication while any attempt is unresolved.
//
// Everything here is SYNTHETIC except the store, which is a real directory.
//
// usage: unresolved_attempt_recovery <store-directory>

#include "example_support.hpp"

using example::check;
using example::must_quantity;
using example::must_scope;
using example::note;
using example::record;
using example::record_status;
using example::Journal;

int main(int argc, char** argv) {
  if (argc < 2) {
    std::printf("usage: unresolved_attempt_recovery <store-directory>\n");
    return 2;
  }
  const std::string root = argv[1];

  const cfm::ScopeId pump = must_scope("pump.set.a");
  cfm::CoolingScope scope;
  scope.id = pump;
  scope.kind = cfm::ScopeKind::Loop;
  scope.policy.envelope.min_flow = must_quantity(20000, "mL/s");
  scope.policy.envelope.declared_demand = must_quantity(900000, "W");
  scope.policy.requirements = {
      cfm::EvidenceRequirement{cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(30000)},
      cfm::EvidenceRequirement{cfm::ObservationChannel::PumpStatus, cfm::DurationMilliseconds(30000)},
  };

  cfm::DecisionPolicy policy;
  policy.evidence_window = cfm::DurationMilliseconds(30000);

  cfm::ObservationSet dead_pump;
  record(dead_pump, "obs.flow.1", pump, cfm::ObservationChannel::FlowMeter, 500, "mL/s", 1000, "loop-flow");
  record_status(dead_pump, "obs.pump.1", pump, cfm::ObservationChannel::PumpStatus, 2, 1000, "pump-agent");

  cfm::CoolingFailureState empty;
  empty.evaluated_at = cfm::DecisionClock(0);
  empty.scopes = {scope};

  cfm::DecisionInput base_input;
  base_input.prior = &empty;
  base_input.observations = &dead_pump;
  base_input.policy = policy;
  base_input.clock = cfm::DecisionClock(1000);

  cfm::Result<cfm::DecisionOutcome> first = cfm::evaluate(base_input);
  check(first.has_value(), "the first evaluation succeeded");
  if (!first.has_value()) {
    std::printf("error: %s\n", first.error().to_string().c_str());
    return 1;
  }
  cfm::CoolingFailureState first_state = first->state;

  cfm::Result<Journal> writer = Journal::create(root);
  check(writer.has_value(), "the store was created");
  if (!writer.has_value()) {
    std::printf("error: %s\n", writer.error().to_string().c_str());
    return 1;
  }
  const cfm::WriterEpoch first_epoch = writer->epoch();
  const cfm::WriterIncarnation first_incarnation = writer->incarnation();
  cfm::Result<cfm::PublicationReceipt> published = writer->append(first_state, "pump.start", 1);
  check(published.has_value(), "the first decision was published");
  if (!published.has_value()) {
    std::printf("error: %s\n", published.error().to_string().c_str());
    return 1;
  }

  // The response is solicited and nobody ever answers: this is the request that is
  // in flight when the writer stops.
  cfm::DecisionInput solicited_input = base_input;
  solicited_input.prior = &first_state;
  solicited_input.clock = cfm::DecisionClock(2000);
  cfm::DecisionInput::SolicitationRequest solicitation;
  solicitation.scope = pump;
  solicitation.solicitation = *cfm::MutationId::parse("pump.start.standby");
  solicitation.attempt = *cfm::AttemptOrdinal::parse(1);
  solicitation.action = cfm::ResponseAction::StartStandbyPump;
  solicitation.addressee = "liquid-cooling-control";
  solicited_input.solicitations = {solicitation};

  cfm::Result<cfm::DecisionOutcome> second = cfm::evaluate(solicited_input);
  check(second.has_value(), "the solicitation evaluation succeeded");
  if (!second.has_value()) {
    std::printf("error: %s\n", second.error().to_string().c_str());
    return 1;
  }
  cfm::CoolingFailureState solicited_state = second->state;
  cfm::Result<cfm::PublicationReceipt> in_flight = writer->append(solicited_state, "pump.solicit", 1);
  check(in_flight.has_value(), "the solicited decision was published");
  if (!in_flight.has_value()) {
    std::printf("error: %s\n", in_flight.error().to_string().c_str());
    return 1;
  }
  const cfm::ResponsePlan* plan = cfm::find_plan_for_scope(solicited_state, pump);
  check(plan != nullptr && plan->attempts.size() == 1, "one attempt is in flight");
  const cfm::AttemptId attempt_id =
      plan != nullptr && !plan->attempts.empty() ? plan->attempts.front().id : cfm::AttemptId();
  note("in flight attempt " + attempt_id.str());
  check(cfm::find_plan_for_scope(solicited_state, pump)->attempts.front().state ==
            cfm::AttemptState::Solicited,
        "the attempt is recorded as Solicited, with no outcome observed");

  // The writer stops: the handle is closed and its authority is gone.
  cfm::Result<void> closed = writer->close();
  check(closed.has_value(), "the writer released its lock");

  cfm::Result<Journal> successor = Journal::open(root);
  check(successor.has_value(), "the successor opened the store");
  if (!successor.has_value()) {
    std::printf("error: %s\n", successor.error().to_string().c_str());
    return 1;
  }
  cfm::Result<cfm::StoreInfo> info = successor->info();
  check(info.has_value(), "the successor has store information");
  if (info.has_value()) {
    note("predecessor epoch " + std::to_string(first_epoch.value()) + " incarnation " +
         std::to_string(first_incarnation.value()) + " -> successor epoch " +
         std::to_string(info->epoch.value()) + " incarnation " +
         std::to_string(info->incarnation.value()));
    check(info->epoch.value() > first_epoch.value(), "the successor holds a later epoch");
    check(info->incarnation.value() > first_incarnation.value(),
          "the successor holds a later incarnation");
  }

  cfm::Result<cfm::CoolingFailureState> head = successor->head();
  check(head.has_value(), "the successor reads the head");
  if (!head.has_value()) {
    std::printf("error: %s\n", head.error().to_string().c_str());
    return 1;
  }
  check(!head->unresolved_attempts.empty(), "the head still names the in-flight attempt");
  note("head unresolved attempts " + std::to_string(head->unresolved_attempts.size()));

  // A publication that does not resolve the attempt is refused.
  cfm::Result<cfm::PublicationReceipt> refused = successor->append(head.value(), "pump.unrelated", 1);
  check(!refused.has_value(), "a fresh publication is refused while an attempt is unresolved");
  if (!refused.has_value()) {
    note("refusal: " + refused.error().to_string());
  }

  // The successor evaluates with authority_changed, which adopts the attempt as
  // Unresolved. Nothing is redispatched.
  const cfm::CoolingFailureState& head_state = head.value();
  cfm::DecisionInput successor_input = solicited_input;
  successor_input.prior = &head_state;
  successor_input.clock = cfm::DecisionClock(3000);
  successor_input.authority_changed = true;
  successor_input.solicitations.clear();
  cfm::Result<cfm::DecisionOutcome> adopted = cfm::evaluate(successor_input);
  check(adopted.has_value(), "the successor evaluation succeeded");
  if (!adopted.has_value()) {
    std::printf("error: %s\n", adopted.error().to_string().c_str());
    return 1;
  }
  cfm::CoolingFailureState adopted_state = adopted->state;
  const cfm::ResponsePlan* adopted_plan = cfm::find_plan_for_scope(adopted_state, pump);
  check(adopted_plan != nullptr && !adopted_plan->attempts.empty(), "the attempt is still recorded");
  if (adopted_plan != nullptr && !adopted_plan->attempts.empty()) {
    check(adopted_plan->attempts.front().state == cfm::AttemptState::Unresolved,
          "an in-flight attempt becomes Unresolved under a new authority");
    check(adopted_plan->attempts.front().adopted_after_restart,
          "the attempt records that it was adopted after a restart");
  }
  check(adopted_state.unresolved_attempts.size() == 1,
        "the adopted state names exactly one unresolved attempt");

  // Soliciting a second request before the first is resolved is refused: a lost
  // response must not become two consequential actions.
  cfm::DecisionInput premature = successor_input;
  premature.prior = &adopted_state;
  premature.clock = cfm::DecisionClock(3500);
  cfm::DecisionInput::SolicitationRequest second_request;
  second_request.scope = pump;
  second_request.solicitation = *cfm::MutationId::parse("pump.start.standby.second");
  second_request.attempt = *cfm::AttemptOrdinal::parse(1);
  second_request.action = cfm::ResponseAction::StartStandbyPump;
  second_request.addressee = "liquid-cooling-control";
  premature.solicitations = {second_request};
  cfm::Result<cfm::DecisionOutcome> rejected = cfm::evaluate(premature);
  check(!rejected.has_value(),
        "a second request is refused while the first attempt is still unresolved");
  if (!rejected.has_value()) {
    note("second-request refusal: " + rejected.error().to_string());
  } else {
    note("second request was accepted: " + std::to_string(rejected->state.plans.size()) + " plan(s)");
  }

  // The explicit resolution is the only way forward.
  cfm::DecisionInput resolve = successor_input;
  resolve.prior = &adopted_state;
  resolve.clock = cfm::DecisionClock(4000);
  resolve.solicitations = {solicitation};
  cfm::DecisionInput::AttemptReport report;
  report.attempt = attempt_id;
  report.state = cfm::AttemptState::Failed;
  report.at = cfm::DecisionClock(4000);
  report.verdict = "standby pump start was never observed to take effect";
  resolve.attempt_reports = {report};
  cfm::Result<cfm::DecisionOutcome> resolved = cfm::evaluate(resolve);
  check(resolved.has_value(), "the explicit resolution succeeded");
  if (!resolved.has_value()) {
    std::printf("error: %s\n", resolved.error().to_string().c_str());
    return 1;
  }
  cfm::Result<cfm::PublicationReceipt> published_resolution =
      successor->append(resolved->state, "pump.resolve", 1);
  check(published_resolution.has_value(), "the resolution was published");
  if (published_resolution.has_value()) {
    note("resolved generation " + std::to_string(published_resolution->generation.value()));
  }
  cfm::Result<cfm::CoolingFailureState> resolved_head = successor->head();
  check(resolved_head.has_value() && resolved_head->unresolved_attempts.empty(),
        "no attempt remains unresolved after the resolution");

  note("");
  note("The sequence is the contract: an outcome nobody observed stays unknown, a new authority");
  note("adopts it explicitly, and no path in this component redispatches it by itself.");

  if (example::failures == 0) {
    std::printf("example unresolved_attempt_recovery ok\n");
    return 0;
  }
  std::printf("example unresolved_attempt_recovery FAILED: %d check(s)\n", example::failures);
  return 1;
}
