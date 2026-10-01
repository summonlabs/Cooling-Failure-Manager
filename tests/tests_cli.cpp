// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The cfmctl inspection tool.
//
// These cases run the real executable as an independent OS process and read what
// it printed and what status it returned. The tool's exit codes are part of its
// contract, so a refusal is checked by code and not only by wording.

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "dccp/cooling_failure_manager/canonical.hpp"
#include "dccp/cooling_failure_manager/store.hpp"
#include "dccp/cooling_failure_manager/text.hpp"
#include "dccp/cooling_failure_manager/version.hpp"

#include "child_process.hpp"
#include "test_framework.hpp"

namespace {

#ifndef COOLING_FAILURE_MANAGER_CLI_PATH
#error "COOLING_FAILURE_MANAGER_CLI_PATH must be defined by the build for the CLI tests"
#endif

const char* cli_path() { return COOLING_FAILURE_MANAGER_CLI_PATH; }

/// Runs cfmctl with the given arguments and returns its exit status and output.
struct CliRun {
  int exit_code = -1;
  std::string output;
};

CliRun run_cli(const std::vector<std::string>& arguments) {
  std::vector<std::string> argv{cli_path()};
  for (const std::string& argument : arguments) {
    argv.push_back(argument);
  }
  ct_test::Result<ct_test::ChildProcess> child = ct_test::ChildProcess::spawn(argv);
  CT_REQUIRE(child.has_value());
  const ct_test::ChildResult result = child->collect();
  CliRun run;
  run.exit_code = result.exit_code;
  run.output = result.output;
  return run;
}

std::string scratch_directory(std::string_view name) {
  const std::string root =
      (std::filesystem::current_path() / ("cli-" + std::string(name))).string();
  std::error_code ignored;
  std::filesystem::remove_all(root, ignored);
  std::filesystem::create_directories(root, ignored);
  return root;
}

void write_text(const std::string& path, std::string_view content) {
  std::FILE* file = nullptr;
#if defined(_WIN32)
  if (fopen_s(&file, path.c_str(), "wb") != 0) {
    file = nullptr;
  }
#else
  file = std::fopen(path.c_str(), "wb");
#endif
  CT_REQUIRE(file != nullptr);
  std::fwrite(content.data(), 1, content.size(), file);
  std::fclose(file);
}

std::string read_text(const std::string& path) {
  std::FILE* file = nullptr;
#if defined(_WIN32)
  if (fopen_s(&file, path.c_str(), "rb") != 0) {
    file = nullptr;
  }
#else
  file = std::fopen(path.c_str(), "rb");
#endif
  if (file == nullptr) {
    return std::string();
  }
  std::string content;
  char buffer[4096];
  while (true) {
    const std::size_t read = std::fread(buffer, 1, sizeof(buffer), file);
    if (read > 0) {
      content.append(buffer, read);
    }
    if (read < sizeof(buffer)) {
      break;
    }
  }
  std::fclose(file);
  return content;
}

/// A scenario file that exercises the whole evaluation path: two scopes, a lost
/// loop, a declared dependency, evidence on several channels and a recovery
/// request.
std::string scenario_text() {
  return std::string(
      "# Cooling Failure Manager synthetic scenario\n"
      "clock = 1000000000\n"
      "evidence-window = 60000\n"
      "confirm-min-observations = 1\n"
      "safety-escalation-severity = critical\n"
      "binding = cooling-topology=cooling-topology:site.cli:4\n"
      "observed-binding = cooling-topology=cooling-topology:site.cli:4\n"
      "\n"
      "[scope]\n"
      "id = plant.cli\n"
      "kind = plant\n"
      "name = Synthetic plant\n"
      "declared-demand = 5000000:W\n"
      "require = chiller-status:60000\n"
      "require = thermal-capacity-meter:60000\n"
      "\n"
      "[scope]\n"
      "id = loop.cli\n"
      "kind = loop\n"
      "name = Synthetic loop\n"
      "min-flow = 30000:mL/s\n"
      "min-differential-pressure = 50000:Pa-dp\n"
      "declared-demand = 2000000:W\n"
      "min-thermal-margin = 2000:mK\n"
      "max-supply-temperature = 25000:mC\n"
      "dwell = 300000\n"
      "hysteresis = 120000\n"
      "require = flow-meter:60000\n"
      "require = differential-pressure:60000\n"
      "require = leak-detector:60000\n"
      "require = thermal-capacity-meter:60000\n"
      "depends-on = plant.cli:supplies-coolant:1000000\n"
      "\n"
      "[observation]\n"
      "id = cli.chiller\n"
      "scope = plant.cli\n"
      "channel = chiller-status\n"
      "value = 2\n"
      "at = 999999000\n"
      "producer = synthetic-bms\n"
      "\n"
      "[observation]\n"
      "id = cli.flow\n"
      "scope = loop.cli\n"
      "channel = flow-meter\n"
      "value = 0\n"
      "unit = mL/s\n"
      "at = 999999000\n"
      "producer = synthetic-flow\n"
      "\n"
      "[observation]\n"
      "id = cli.dp\n"
      "scope = loop.cli\n"
      "channel = differential-pressure\n"
      "value = 0\n"
      "unit = Pa-dp\n"
      "at = 999999000\n"
      "producer = synthetic-flow\n"
      "\n"
      "[observation]\n"
      "id = cli.leak\n"
      "scope = loop.cli\n"
      "channel = leak-detector\n"
      "leak = leak-active\n"
      "at = 999999000\n"
      "producer = synthetic-leak\n"
      "\n"
      "[recovery-request]\n"
      "scope = loop.cli\n"
      "\n"
      "[stable-since]\n"
      "scope = loop.cli\n"
      "since = 999999000\n");
}

}  // namespace

CT_TEST(cli_version_reports_the_boundary) {
  const CliRun run = run_cli({"version"});
  CT_CHECK_EQ(run.exit_code, 0);
  CT_CHECK(run.output.find("cfmctl") != std::string::npos);
  CT_CHECK(run.output.find("1.0.1") != std::string::npos);
  CT_CHECK(run.output.find("no actuation") != std::string::npos);
  CT_CHECK(run.output.find("dccp-cooling-failure-state") != std::string::npos);
}

CT_TEST(cli_usage_and_bad_options_are_usage_failures) {
  const CliRun no_arguments = run_cli({});
  CT_CHECK_EQ(no_arguments.exit_code, 2);
  CT_CHECK(no_arguments.output.find("usage: cfmctl") != std::string::npos);
  const CliRun help = run_cli({"--help"});
  CT_CHECK_EQ(help.exit_code, 0);
  const CliRun unknown = run_cli({"nonsense"});
  CT_CHECK_EQ(unknown.exit_code, 2);
  const CliRun unknown_option = run_cli({"version", "--nonsense"});
  CT_CHECK_EQ(unknown_option.exit_code, 2);
  const CliRun missing_scenario = run_cli({"evaluate"});
  CT_CHECK_EQ(missing_scenario.exit_code, 2);
}

CT_TEST(cli_evaluates_a_scenario_and_reports_the_classification) {
  const std::string directory = scratch_directory("evaluate");
  const std::string scenario = (std::filesystem::path(directory) / "scenario.cfm").string();
  write_text(scenario, scenario_text());

  const CliRun run = run_cli({"evaluate", "--scenario=" + scenario, "--explain"});
  CT_CHECK_EQ(run.exit_code, 0);
  CT_CHECK(run.output.find("scope loop.cli") != std::string::npos);
  CT_CHECK(run.output.find("confirmed ") != std::string::npos);
  // The four class buckets are rendered with the tool's own wording.
  CT_CHECK(run.output.find("gap       ") != std::string::npos);
  CT_CHECK(run.output.find("severity") != std::string::npos);
  CT_CHECK(run.output.find("recovery") != std::string::npos);
  CT_CHECK(run.output.find("-- explanation") != std::string::npos);

  // The scenario-only mode validates without evaluating.
  const CliRun validated = run_cli({"evaluate", "--scenario=" + scenario, "--scenario-only"});
  CT_CHECK_EQ(validated.exit_code, 0);
  CT_CHECK(validated.output.find("scenario") != std::string::npos);
  CT_CHECK(validated.output.find("confirmed") == std::string::npos);
}

CT_TEST(cli_canonical_output_round_trips) {
  const std::string directory = scratch_directory("canonical");
  const std::string scenario = (std::filesystem::path(directory) / "scenario.cfm").string();
  write_text(scenario, scenario_text());

  const CliRun run = run_cli({"evaluate", "--scenario=" + scenario, "--canonical"});
  CT_CHECK_EQ(run.exit_code, 0);
  CT_CHECK(run.output.rfind("dccp-cooling-failure-state", 0) == 0);
  CT_CHECK(run.output.find("\nend\t") != std::string::npos);
  // The tool writes its text stream with the platform's line terminator; the
  // canonical body itself uses one LF per line, so the console's CR is removed
  // before the bytes are decoded.
  std::string canonical = run.output;
  canonical.erase(std::remove(canonical.begin(), canonical.end(), '\r'), canonical.end());
  const dccp::cooling_failure_manager::Result<dccp::cooling_failure_manager::CoolingFailureState>
      decoded = dccp::cooling_failure_manager::decode_state(canonical);
  if (!decoded.has_value()) {
    ::ct_test::report_note("canonical output refused: " + decoded.error().to_string());
  }
  CT_CHECK(decoded.has_value());
  if (decoded.has_value()) {
    CT_CHECK(dccp::cooling_failure_manager::encode_state(decoded.value()) == canonical);
  }
}

CT_TEST(cli_refuses_a_malformed_scenario) {
  const std::string directory = scratch_directory("malformed");
  const std::string scenario = (std::filesystem::path(directory) / "bad.cfm").string();
  write_text(scenario,
             "[scope]\n"
             "id = loop.cli\n"
             "kind = not-a-kind\n");
  const CliRun bad_token = run_cli({"evaluate", "--scenario=" + scenario});
  CT_CHECK_EQ(bad_token.exit_code, 3);
  CT_CHECK(bad_token.output.find("error:") != std::string::npos);

  write_text(scenario,
             "[scope]\n"
             "id = loop.cli\n"
             "this is not an assignment\n");
  const CliRun bad_line = run_cli({"evaluate", "--scenario=" + scenario});
  CT_CHECK_EQ(bad_line.exit_code, 3);

  write_text(scenario, "[nowhere]\nid = loop.cli\n");
  const CliRun bad_section = run_cli({"evaluate", "--scenario=" + scenario});
  CT_CHECK_EQ(bad_section.exit_code, 3);

  // A scenario whose file does not exist is an input failure, not a crash.
  const CliRun missing = run_cli({"evaluate", "--scenario=" +
                                              (std::filesystem::path(directory) / "absent.cfm").string()});
  CT_CHECK_EQ(missing.exit_code, 3);
}

CT_TEST(cli_publishes_and_inspects_a_store) {
  const std::string directory = scratch_directory("store");
  const std::string scenario = (std::filesystem::path(directory) / "scenario.cfm").string();
  const std::string store_root = (std::filesystem::path(directory) / "store").string();
  write_text(scenario, scenario_text());

  // The store must exist before the tool can publish into it; a directory the tool
  // creates itself would be a policy decision the operator has not made.
  std::error_code ignored;
  std::filesystem::create_directories(store_root, ignored);
  const CliRun created = run_cli({"inspect", "--store=" + store_root, "--verify"});
  CT_CHECK(created.exit_code != 0);

  // Initialise the store through the library, then publish through the tool.
  dccp::cooling_failure_manager::StoreOptions options;
  options.root = store_root;
  const dccp::cooling_failure_manager::Result<dccp::cooling_failure_manager::StoreId> store_id =
      dccp::cooling_failure_manager::StoreId::parse("cli.store");
  CT_REQUIRE(store_id.has_value());
  dccp::cooling_failure_manager::Result<dccp::cooling_failure_manager::Store> store =
      dccp::cooling_failure_manager::Store::create(options, store_id.value());
  CT_REQUIRE(store.has_value());
  CT_REQUIRE(store->close().has_value());

  const CliRun published = run_cli({"evaluate", "--scenario=" + scenario, "--publish",
                                    "--store=" + store_root, "--mutation=cli.publish",
                                    "--attempt=1"});
  CT_CHECK_EQ(published.exit_code, 0);
  CT_CHECK(published.output.find("published generation 1") != std::string::npos);
  CT_CHECK(published.output.find("durable") != std::string::npos);

  const CliRun inspected = run_cli({"inspect", "--store=" + store_root});
  CT_CHECK_EQ(inspected.exit_code, 0);
  CT_CHECK(inspected.output.find("cli.store") != std::string::npos);
  CT_CHECK(inspected.output.find("head 1") != std::string::npos);
  CT_CHECK(inspected.output.find("scope loop.cli") != std::string::npos);

  const CliRun verified = run_cli({"inspect", "--store=" + store_root, "--verify"});
  CT_CHECK_EQ(verified.exit_code, 0);
  CT_CHECK(verified.output.find("verify ok") != std::string::npos);
  CT_CHECK(verified.output.find("head verified        yes") != std::string::npos);
  CT_CHECK(verified.output.find("canonical fixed point yes") != std::string::npos);

  const CliRun explained = run_cli({"explain", "--store=" + store_root, "--scope=loop.cli"});
  CT_CHECK_EQ(explained.exit_code, 0);
  CT_CHECK(explained.output.find("severity=") != std::string::npos);

  const CliRun recovered = run_cli({"recover", "--store=" + store_root});
  CT_CHECK_EQ(recovered.exit_code, 0);
  CT_CHECK(recovered.output.find("no-action") != std::string::npos);
  CT_CHECK(recovered.output.find("floor-respected") != std::string::npos);
}

CT_TEST(cli_publishing_is_idempotent_for_one_attempt) {
  const std::string directory = scratch_directory("idempotent");
  const std::string scenario = (std::filesystem::path(directory) / "scenario.cfm").string();
  const std::string store_root = (std::filesystem::path(directory) / "store").string();
  write_text(scenario, scenario_text());
  std::error_code ignored;
  std::filesystem::create_directories(store_root, ignored);
  dccp::cooling_failure_manager::StoreOptions options;
  options.root = store_root;
  dccp::cooling_failure_manager::Result<dccp::cooling_failure_manager::Store> store =
      dccp::cooling_failure_manager::Store::create(
          options, dccp::cooling_failure_manager::StoreId::parse("cli.store").value());
  CT_REQUIRE(store.has_value());
  CT_REQUIRE(store->close().has_value());

  const std::vector<std::string> arguments = {"evaluate", "--scenario=" + scenario, "--publish",
                                              "--store=" + store_root, "--mutation=cli.replay",
                                              "--attempt=1"};
  const CliRun first = run_cli(arguments);
  CT_CHECK_EQ(first.exit_code, 0);
  const CliRun second = run_cli(arguments);
  CT_CHECK_EQ(second.exit_code, 0);
  // The second run is the same already-committed operation, so it replays rather
  // than publishing a second generation.
  CT_CHECK(second.output.find("replayed") != std::string::npos);
  const CliRun inspected = run_cli({"inspect", "--store=" + store_root});
  CT_CHECK_EQ(inspected.exit_code, 0);
  CT_CHECK(inspected.output.find("head 1") != std::string::npos);
}

CT_TEST(cli_reconciles_an_unresolved_attempt) {
  const std::string directory = scratch_directory("reconcile");
  const std::string store_root = (std::filesystem::path(directory) / "store").string();
  std::error_code ignored;
  std::filesystem::create_directories(store_root, ignored);
  dccp::cooling_failure_manager::StoreOptions options;
  options.root = store_root;
  dccp::cooling_failure_manager::Result<dccp::cooling_failure_manager::Store> store =
      dccp::cooling_failure_manager::Store::create(
          options, dccp::cooling_failure_manager::StoreId::parse("cli.store").value());
  CT_REQUIRE(store.has_value());

  // Publish a state that carries an in-flight attempt.
  dccp::cooling_failure_manager::PublicationRequest request;
  request.epoch = store->epoch();
  request.incarnation = store->incarnation();
  request.mutation = dccp::cooling_failure_manager::MutationId::parse("cli.seed").value();
  request.attempt = dccp::cooling_failure_manager::AttemptOrdinal::parse(1).value();
  dccp::cooling_failure_manager::CoolingFailureState body;
  // A published state carries the clock it was decided at; a state without one is
  // not a state, and the decoder refuses it rather than inventing a time.
  body.evaluated_at = dccp::cooling_failure_manager::DecisionClock(1000);
  dccp::cooling_failure_manager::ResponsePlan plan;
  plan.updated_at = dccp::cooling_failure_manager::DecisionClock(1000);
  plan.id = dccp::cooling_failure_manager::PlanId::parse("plan.cli").value();
  plan.scope = dccp::cooling_failure_manager::ScopeId::parse("loop.cli").value();
  dccp::cooling_failure_manager::ScopeId scope_id = plan.scope;
  dccp::cooling_failure_manager::CoolingScope scope;
  scope.id = scope_id;
  scope.kind = dccp::cooling_failure_manager::ScopeKind::Loop;
  body.scopes.push_back(scope);
  dccp::cooling_failure_manager::ResponseAttempt attempt;
  attempt.id = dccp::cooling_failure_manager::AttemptId::parse("at.cli").value();
  attempt.solicitation = dccp::cooling_failure_manager::MutationId::parse("cli.solicit").value();
  attempt.attempt = dccp::cooling_failure_manager::AttemptOrdinal::parse(1).value();
  attempt.action = dccp::cooling_failure_manager::ResponseAction::StartStandbyPump;
  attempt.state = dccp::cooling_failure_manager::AttemptState::Solicited;
  attempt.addressee = "liquid-cooling-control";
  attempt.solicited_at = dccp::cooling_failure_manager::DecisionClock(900);
  attempt.updated_at = dccp::cooling_failure_manager::DecisionClock(900);
  plan.attempts.push_back(attempt);
  body.plans.push_back(plan);
  // The state the handle is about to publish must itself be a state the decoder
  // accepts; checking it here separates a bad body from a bad publication. The
  // body is attached to the request first, because a request with an empty body
  // is a different publication from one carrying this state.
  request.body = body;
  {
    const std::string preflight = dccp::cooling_failure_manager::encode_state(request.body);
    const dccp::cooling_failure_manager::Result<dccp::cooling_failure_manager::CoolingFailureState>
        preflight_decoded = dccp::cooling_failure_manager::decode_state(preflight);
    if (!preflight_decoded.has_value()) {
      ::ct_test::report_note("preflight body refused: " + preflight_decoded.error().to_string());
    }
    CT_CHECK(preflight_decoded.has_value());
  }
  dccp::cooling_failure_manager::Result<dccp::cooling_failure_manager::PublicationReceipt> receipt =
      store->publish(request);
  if (!receipt.has_value()) {
    std::string detail = "seed publication refused: " + receipt.error().to_string();
    for (const std::string& item : receipt.error().details()) {
      detail += " | " + item;
    }
    ::ct_test::report_note(detail);
  }
  CT_REQUIRE(receipt.has_value());
  CT_REQUIRE(store->close().has_value());

  const CliRun reconciled = run_cli({"reconcile", "--store=" + store_root,
                                     "--mutation=cli.reconcile", "--attempt=1"});
  CT_CHECK_EQ(reconciled.exit_code, 0);
  CT_CHECK(reconciled.output.find("reconciled attempts 1") != std::string::npos);
  const CliRun inspected = run_cli({"inspect", "--store=" + store_root});
  CT_CHECK(inspected.output.find("unresolved attempt at.cli") != std::string::npos);

  const CliRun missing_arguments = run_cli({"reconcile", "--store=" + store_root});
  CT_CHECK_EQ(missing_arguments.exit_code, 2);
}
