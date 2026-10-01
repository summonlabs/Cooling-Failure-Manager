// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Adversarial tests: malformed, truncated, corrupt and hostile input.
//
// Every case here feeds the library something it should refuse, and checks that it
// refuses with the right code and leaves nothing behind. A library that accepts a
// damaged state is worse than one that crashes, because the damaged state is
// thereafter indistinguishable from a real one.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
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
#include "dccp/cooling_failure_manager/store.hpp"
#include "dccp/cooling_failure_manager/text.hpp"

#include "test_framework.hpp"

namespace cfm = dccp::cooling_failure_manager;

namespace {

constexpr std::int64_t kAdvClock = 3000000000;
constexpr std::int64_t kAdvWindow = 60000;

const cfm::ScopeId kAdvLoop = *cfm::ScopeId::parse("loop.adv");

cfm::CoolingScope adv_scope() {
  cfm::CoolingScope scope;
  scope.id = kAdvLoop;
  scope.kind = cfm::ScopeKind::Loop;
  scope.policy.envelope.min_flow = *cfm::DeclaredQuantity::make(30000, "mL/s");
  scope.policy.envelope.min_differential_pressure = *cfm::DeclaredQuantity::make(50000, "Pa-dp");
  scope.policy.envelope.declared_demand = *cfm::DeclaredQuantity::make(2000000, "W");
  scope.policy.requirements = {
      {cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(kAdvWindow)},
      {cfm::ObservationChannel::DifferentialPressure, cfm::DurationMilliseconds(kAdvWindow)}};
  return scope;
}

cfm::DecisionPolicy adv_policy() {
  cfm::DecisionPolicy policy;
  policy.evidence_window = cfm::DurationMilliseconds(kAdvWindow);
  policy.confirm_min_observations = 1;
  return policy;
}

cfm::CoolingFailureState adv_state() {
  cfm::CoolingFailureState skeleton;
  skeleton.evaluated_at = cfm::DecisionClock(kAdvClock);
  skeleton.scopes = {adv_scope()};
  cfm::ObservationSet observations;
  cfm::Observation observation;
  observation.id = *cfm::ObservationId::parse("adv.flow");
  observation.scope = kAdvLoop;
  observation.channel = cfm::ObservationChannel::FlowMeter;
  observation.quantity = *cfm::Quantity::observed(0, "mL/s", cfm::ObservationQuality::Good,
                                                 cfm::ObservationSequence(1));
  observation.observed_at = cfm::DecisionClock(kAdvClock - 1000);
  observation.recorded_at = cfm::DecisionClock(kAdvClock);
  observation.producer = "adv.producer";
  observation.sensor = "adv.sensor";
  observation.evidence_generation = cfm::EvidenceGeneration(1);
  CT_REQUIRE(observations.add(observation).has_value());
  cfm::DecisionInput input;
  input.prior = &skeleton;
  input.observations = &observations;
  input.policy = adv_policy();
  input.clock = cfm::DecisionClock(kAdvClock);
  cfm::Result<cfm::DecisionOutcome> outcome = cfm::evaluate(input);
  CT_REQUIRE(outcome.has_value());
  return outcome.value().state;
}

std::string adv_root(std::string_view name) {
  const std::string root =
      (std::filesystem::current_path() / ("adv-store-" + std::string(name))).string();
  std::error_code ignored;
  std::filesystem::remove_all(root, ignored);
  std::filesystem::create_directories(root, ignored);
  return root;
}

}  // namespace

// ===========================================================================
// Malformed canonical input
// ===========================================================================

CT_TEST(adversarial_canonical_rejects_every_single_byte_mutation) {
  const cfm::CoolingFailureState state = adv_state();
  const std::string encoded = cfm::encode_state(state);
  CT_REQUIRE(encoded.size() > 32);
  std::size_t mutations = 0;
  for (std::size_t offset = 0; offset < encoded.size(); ++offset) {
    for (const unsigned int mask : {0x01u, 0x80u}) {
      std::string damaged = encoded;
      damaged[offset] = static_cast<char>(
          static_cast<unsigned int>(static_cast<unsigned char>(damaged[offset])) ^ mask);
      if (damaged == encoded) {
        continue;
      }
      ++mutations;
      const cfm::Result<cfm::CoolingFailureState> decoded = cfm::decode_state(damaged);
      CT_CHECK_MSG(!decoded.has_value(), "a single-byte mutation at offset " +
                                             std::to_string(offset) + " was accepted");
      if (decoded.has_value()) {
        // A mutation that survives decoding must at least not be the same state.
        CT_CHECK(!(cfm::state_digest(decoded.value()) == cfm::state_digest(state)));
      }
    }
  }
  CT_CHECK(mutations > 0);
}

CT_TEST(adversarial_canonical_rejects_framing_damage) {
  const cfm::CoolingFailureState state = adv_state();
  const std::string encoded = cfm::encode_state(state);

  // Remove the final newline.
  CT_CHECK(!cfm::decode_state(encoded.substr(0, encoded.size() - 1)).has_value());
  // Add trailing content after the end record.
  CT_CHECK(!cfm::decode_state(encoded + "trailing\n").has_value());
  // Truncate the digest.
  CT_CHECK(!cfm::decode_state(encoded.substr(0, encoded.size() - 10)).has_value());
  // Uppercase the digest: hex is lowercase only.
  std::string uppercase = encoded;
  for (char& byte : uppercase) {
    if (byte >= 'a' && byte <= 'f') {
      byte = static_cast<char>(byte - 'a' + 'A');
    }
  }
  CT_CHECK(!cfm::decode_state(uppercase).has_value());
  // Replace a separator with a space.
  std::string spaced = encoded;
  spaced[spaced.find('\t')] = ' ';
  CT_CHECK(!cfm::decode_state(spaced).has_value());
  // An absurdly large declared count.
  std::string huge_count = encoded;
  const std::size_t end_position = huge_count.find("\nend\t");
  CT_REQUIRE(end_position != std::string::npos);
  const std::size_t digest_start = huge_count.find('\t', end_position + 5);
  CT_REQUIRE(digest_start != std::string::npos);
  huge_count.replace(end_position + 5, digest_start - (end_position + 5), "18446744073709551615");
  CT_CHECK(!cfm::decode_state(huge_count).has_value());
  // A body larger than the accepted bound is refused before it is parsed.
  std::string oversized(static_cast<std::size_t>(cfm::limits::kMaxGenerationBytes) + 1, 'x');
  CT_CHECK(!cfm::decode_state(oversized).has_value());
}

// ===========================================================================
// Structural hostility
// ===========================================================================

CT_TEST(adversarial_structure_rejects_duplicates_cycles_and_dangling_references) {
  cfm::CoolingFailureState state;
  state.scopes = {adv_scope()};

  // A duplicate scope identity.
  cfm::CoolingFailureState duplicate = state;
  duplicate.scopes.push_back(adv_scope());
  CT_CHECK(!cfm::canonicalize(duplicate).has_value());

  // A dependency cycle.
  cfm::CoolingFailureState cyclic;
  cfm::CoolingScope first = adv_scope();
  cfm::CoolingScope second = adv_scope();
  second.id = *cfm::ScopeId::parse("loop.adv.2");
  first.dependencies.push_back(
      cfm::ScopeDependency{second.id, cfm::DependencyKind::SuppliesCoolant, 1000000});
  second.dependencies.push_back(
      cfm::ScopeDependency{first.id, cfm::DependencyKind::SuppliesCoolant, 1000000});
  cyclic.scopes = {first, second};
  CT_REQUIRE(cfm::canonicalize(cyclic).has_value());
  const cfm::Result<void> cycle_result = cfm::validate_structure(cyclic);
  CT_CHECK(!cycle_result.has_value());
  if (!cycle_result.has_value()) {
    CT_CHECK(cycle_result.error().code() == cfm::ErrorCode::ScopeCycle);
  }

  // A self-dependency.
  cfm::CoolingFailureState selfish;
  cfm::CoolingScope self = adv_scope();
  self.dependencies.push_back(
      cfm::ScopeDependency{self.id, cfm::DependencyKind::SharesReturn, 1000000});
  selfish.scopes = {self};
  CT_CHECK(!cfm::validate_structure(selfish).has_value());

  // A dependency naming a scope that does not exist.
  cfm::CoolingFailureState dangling;
  cfm::CoolingScope orphan = adv_scope();
  orphan.dependencies.push_back(cfm::ScopeDependency{*cfm::ScopeId::parse("loop.absent"),
                                                    cfm::DependencyKind::SharesPlant, 500000});
  dangling.scopes = {orphan};
  const cfm::Result<void> dangling_result = cfm::validate_structure(dangling);
  CT_CHECK(!dangling_result.has_value());

  // A plan that answers a failure of another scope.
  cfm::CoolingFailureState mismatched;
  mismatched.scopes = {adv_scope()};
  cfm::CoolingFailure failure;
  failure.id = *cfm::FailureId::parse("adv.failure");
  failure.scope = kAdvLoop;
  failure.failure_class = cfm::FailureClass::LoopLoss;
  failure.confirmation = cfm::ConfirmationState::Confirmed;
  failure.severity = cfm::Severity::Total;
  mismatched.failures.push_back(failure);
  cfm::ResponsePlan plan;
  plan.id = *cfm::PlanId::parse("adv.plan");
  plan.scope = *cfm::ScopeId::parse("loop.other");
  plan.failures = {failure.id};
  mismatched.plans.push_back(plan);
  CT_CHECK(!cfm::validate_structure(mismatched).has_value());
}

CT_TEST(adversarial_quantities_reject_extremes_and_unknown_units) {
  // Values at and beyond every documented bound.
  const std::int64_t flow_max = cfm::limits::kMaxFlowMillilitresPerSecond;
  CT_CHECK(cfm::Quantity::observed(flow_max, "mL/s", cfm::ObservationQuality::Good,
                                   cfm::ObservationSequence(1))
               .has_value());
  CT_CHECK(!cfm::Quantity::observed(flow_max + 1, "mL/s", cfm::ObservationQuality::Good,
                                    cfm::ObservationSequence(1))
                .has_value());
  CT_CHECK(!cfm::Quantity::observed(INT64_MIN, "mL/s", cfm::ObservationQuality::Good,
                                    cfm::ObservationSequence(1))
                .has_value());
  CT_CHECK(!cfm::Quantity::observed(0, "furlongs", cfm::ObservationQuality::Good,
                                    cfm::ObservationSequence(1))
                .has_value());
  // An empty unit is the spelling of a discrete state code and is accepted; a
  // code outside the documented 0/1/2 domain is not.
  const cfm::Result<cfm::Quantity> state_code =
      cfm::Quantity::observed(2, std::string_view(), cfm::ObservationQuality::Good,
                              cfm::ObservationSequence(1));
  CT_CHECK(state_code.has_value());
  CT_CHECK(!cfm::Quantity::observed(3, std::string_view(), cfm::ObservationQuality::Good,
                                    cfm::ObservationSequence(1))
                .has_value());
  CT_CHECK(!cfm::Quantity::observed(-1, std::string_view(), cfm::ObservationQuality::Good,
                                    cfm::ObservationSequence(1))
                .has_value());
  // A declared quantity in an unknown unit is refused; an undeclared one is not a
  // quantity at all.
  CT_CHECK(!cfm::DeclaredQuantity::make(1, "furlongs").has_value());
  CT_CHECK(!cfm::DeclaredQuantity::make(1, "").has_value());
  CT_CHECK(cfm::DeclaredQuantity::make(flow_max, "mL/s").has_value());
  CT_CHECK(!cfm::DeclaredQuantity::make(flow_max + 1, "mL/s").has_value());
  // A temperature outside its declared envelope bound.
  CT_CHECK(!cfm::DeclaredQuantity::make(cfm::limits::kMaxTemperatureMilliCelsius + 1, "mC").has_value());
  CT_CHECK(!cfm::DeclaredQuantity::make(cfm::limits::kMinTemperatureMilliCelsius - 1, "mC").has_value());
}

CT_TEST(adversarial_observation_set_enforces_every_bound_atomically) {
  cfm::ObservationSet set;
  // A batch containing an intra-batch duplicate changes nothing.
  std::vector<cfm::Observation> batch;
  for (std::size_t index = 0; index < 4; ++index) {
    cfm::Observation observation;
    observation.id = *cfm::ObservationId::parse("adv.batch." + cfm::to_decimal(
                                                     static_cast<std::uint64_t>(index % 2)));
    observation.scope = kAdvLoop;
    observation.channel = cfm::ObservationChannel::FlowMeter;
    observation.quantity = *cfm::Quantity::observed(1000, "mL/s", cfm::ObservationQuality::Good,
                                                   cfm::ObservationSequence(1));
    observation.observed_at = cfm::DecisionClock(kAdvClock - 1000);
    observation.recorded_at = cfm::DecisionClock(kAdvClock);
    observation.producer = "adv.batch";
    observation.sensor = "adv.batch.sensor";
    observation.evidence_generation = cfm::EvidenceGeneration(1);
    batch.push_back(observation);
  }
  const cfm::Result<void> refused = set.add_all(batch);
  CT_CHECK(!refused.has_value());
  CT_CHECK_EQ(set.size(), static_cast<std::size_t>(0));

  // An empty identity is refused.
  cfm::Observation empty_id;
  empty_id.scope = kAdvLoop;
  empty_id.channel = cfm::ObservationChannel::FlowMeter;
  empty_id.quantity = cfm::Quantity::indeterminate();
  empty_id.observed_at = cfm::DecisionClock(kAdvClock);
  empty_id.recorded_at = cfm::DecisionClock(kAdvClock);
  CT_CHECK(!set.add(empty_id).has_value());

  // A reading whose unit disagrees with its channel is refused by make_observation.
  cfm::Observation mismatched;
  mismatched.id = *cfm::ObservationId::parse("adv.mismatch");
  mismatched.scope = kAdvLoop;
  mismatched.channel = cfm::ObservationChannel::FlowMeter;
  mismatched.quantity = *cfm::Quantity::observed(1, "Pa", cfm::ObservationQuality::Good,
                                                cfm::ObservationSequence(1));
  mismatched.observed_at = cfm::DecisionClock(kAdvClock);
  mismatched.recorded_at = cfm::DecisionClock(kAdvClock);
  mismatched.producer = "adv.producer";
  mismatched.sensor = "adv.sensor";
  mismatched.evidence_generation = cfm::EvidenceGeneration(1);
  CT_CHECK(!cfm::make_observation(mismatched.id, mismatched.scope, mismatched.channel,
                                  mismatched.quantity, mismatched.leak, mismatched.observed_at,
                                  mismatched.recorded_at, mismatched.producer, mismatched.sensor,
                                  mismatched.evidence_generation, false)
                .has_value());
}

// ===========================================================================
// Store hostility
// ===========================================================================

CT_TEST(adversarial_store_refuses_a_hostile_root_and_duplicate_identity) {
  // A relative root is refused because it would name a different store in every
  // process, which is exactly how two writers would end up on one logical store.
  cfm::StoreOptions relative;
  relative.root = "adv-relative-store";
  CT_CHECK(!cfm::Store::create(relative, *cfm::StoreId::parse("adv.store")).has_value());

  // A traversal component is refused.
  cfm::StoreOptions traversal;
  traversal.root = (std::filesystem::current_path() / ".." / "adv-escape").string();
  CT_CHECK(!cfm::Store::create(traversal, *cfm::StoreId::parse("adv.store")).has_value());

  // A reserved device name is refused.
  cfm::StoreOptions reserved;
  reserved.root = (std::filesystem::current_path() / "NUL").string();
  CT_CHECK(!cfm::Store::create(reserved, *cfm::StoreId::parse("adv.store")).has_value());

  // Creating a store over a directory that already holds one is refused.
  const std::string root = adv_root("duplicate");
  cfm::StoreOptions options;
  options.root = root;
  cfm::Result<cfm::Store> first = cfm::Store::create(options, *cfm::StoreId::parse("adv.store"));
  CT_REQUIRE(first.has_value());
  CT_REQUIRE(first->close().has_value());
  const cfm::Result<cfm::Store> second =
      cfm::Store::create(options, *cfm::StoreId::parse("adv.store.2"));
  CT_CHECK(!second.has_value());
  if (!second.has_value()) {
    CT_CHECK(second.error().code() == cfm::ErrorCode::StoreNotEmpty);
  }
}

CT_TEST(adversarial_store_refuses_a_corrupt_or_foreign_generation) {
  const std::string root = adv_root("corrupt");
  cfm::StoreOptions options;
  options.root = root;
  options.mode = cfm::StoreMode::ReadWrite;
  cfm::Result<cfm::Store> store = cfm::Store::create(options, *cfm::StoreId::parse("adv.store"));
  CT_REQUIRE(store.has_value());
  const cfm::CoolingFailureState state = adv_state();
  cfm::PublicationRequest request;
  request.epoch = store->epoch();
  request.incarnation = store->incarnation();
  request.mutation = *cfm::MutationId::parse("adv.publish");
  request.attempt = *cfm::AttemptOrdinal::parse(1);
  request.body = state;
  CT_REQUIRE(store->publish(request).has_value());

  // Every generation file is damaged in turn and the head must refuse to load.
  const std::filesystem::path generations = std::filesystem::path(root) / "generations";
  CT_REQUIRE(std::filesystem::exists(generations));
  for (const std::filesystem::directory_entry& entry : std::filesystem::directory_iterator(generations)) {
    if (!entry.is_regular_file()) {
      continue;
    }
    const std::string path = entry.path().string();
    const std::string original = [&] {
      std::string content;
      const std::uint64_t size = std::filesystem::file_size(path);
      content.resize(static_cast<std::size_t>(size));
      std::FILE* file = nullptr;
#if defined(_WIN32)
      if (fopen_s(&file, path.c_str(), "rb") != 0) {
        file = nullptr;
      }
#else
      file = std::fopen(path.c_str(), "rb");
#endif
      if (file != nullptr) {
        const std::size_t read = std::fread(content.data(), 1, content.size(), file);
        content.resize(read);
        std::fclose(file);
      }
      return content;
    }();
    CT_REQUIRE(!original.empty());

    for (const double fraction : {0.25, 0.5, 0.9}) {
      const std::size_t offset = static_cast<std::size_t>(static_cast<double>(original.size()) * fraction);
      std::string damaged = original;
      if (offset >= damaged.size()) {
        continue;
      }
      damaged[offset] = static_cast<char>(static_cast<unsigned char>(damaged[offset]) ^ 0x01);
      std::FILE* file = nullptr;
#if defined(_WIN32)
      if (fopen_s(&file, path.c_str(), "wb") != 0) {
        file = nullptr;
      }
#else
      file = std::fopen(path.c_str(), "wb");
#endif
      CT_REQUIRE(file != nullptr);
      std::fwrite(damaged.data(), 1, damaged.size(), file);
      std::fclose(file);
      const cfm::Result<cfm::CoolingFailureState> head = store->head();
      CT_CHECK_MSG(!head.has_value(), "a generation with a flipped byte was adopted");
      // Restore for the next mutation.
      std::FILE* restore = nullptr;
#if defined(_WIN32)
      if (fopen_s(&restore, path.c_str(), "wb") != 0) {
        restore = nullptr;
      }
#else
      restore = std::fopen(path.c_str(), "wb");
#endif
      CT_REQUIRE(restore != nullptr);
      std::fwrite(original.data(), 1, original.size(), restore);
      std::fclose(restore);
    }

    // Truncation at several points.
    for (const double fraction : {0.1, 0.5, 0.95}) {
      const std::size_t size = static_cast<std::size_t>(static_cast<double>(original.size()) * fraction);
      std::FILE* file = nullptr;
#if defined(_WIN32)
      if (fopen_s(&file, path.c_str(), "wb") != 0) {
        file = nullptr;
      }
#else
      file = std::fopen(path.c_str(), "wb");
#endif
      CT_REQUIRE(file != nullptr);
      std::fwrite(original.data(), 1, size, file);
      std::fclose(file);
      CT_CHECK(!store->head().has_value());
      std::FILE* restore = nullptr;
#if defined(_WIN32)
      if (fopen_s(&restore, path.c_str(), "wb") != 0) {
        restore = nullptr;
      }
#else
      restore = std::fopen(path.c_str(), "wb");
#endif
      CT_REQUIRE(restore != nullptr);
      std::fwrite(original.data(), 1, original.size(), restore);
      std::fclose(restore);
    }
  }
  CT_REQUIRE(store->head().has_value());
  CT_REQUIRE(store->close().has_value());
}

CT_TEST(adversarial_store_refuses_an_absurd_configuration) {
  const std::string root = adv_root("config");
  cfm::StoreOptions options;
  options.root = root;
  // A retention of zero would retire the generation it just committed; the store
  // must either refuse it or keep at least the head. Both are acceptable, but the
  // head must never disappear.
  options.retained_generations = 0;
  options.idempotency_retention = 0;
  cfm::Result<cfm::Store> store = cfm::Store::create(options, *cfm::StoreId::parse("adv.store"));
  if (store.has_value()) {
    cfm::PublicationRequest request;
    request.epoch = store->epoch();
    request.incarnation = store->incarnation();
    request.mutation = *cfm::MutationId::parse("adv.config.publish");
    request.attempt = *cfm::AttemptOrdinal::parse(1);
    request.body = adv_state();
    const cfm::Result<cfm::PublicationReceipt> receipt = store->publish(request);
    if (receipt.has_value()) {
      CT_CHECK(store->head().has_value());
    }
    (void)store->close();
  } else {
    // A refusal is also a correct answer for an unrepresentable configuration.
    CT_CHECK(store.error().code() != cfm::ErrorCode::Ok);
  }

  // An absurd generation number is refused rather than wrapped.
  cfm::StoreOptions wide;
  wide.root = adv_root("wide");
  cfm::Result<cfm::Store> second = cfm::Store::create(wide, *cfm::StoreId::parse("adv.store"));
  if (second.has_value()) {
    cfm::PublicationRequest request;
    request.epoch = second->epoch();
    request.incarnation = second->incarnation();
    request.mutation = *cfm::MutationId::parse("adv.wide.publish");
    request.attempt = *cfm::AttemptOrdinal::parse(UINT32_MAX);
    request.base_generation = cfm::StateGeneration(UINT64_MAX);
    request.body = adv_state();
    const cfm::Result<cfm::PublicationReceipt> receipt = second->publish(request);
    CT_CHECK(!receipt.has_value());
    (void)second->close();
  }
}

CT_TEST(adversarial_limits_constant_helpers) {
  // The documented bounds are the values the tests above rely on; this case pins
  // them so a silent change to a bound is a test failure rather than a surprise.
  CT_CHECK_EQ(static_cast<std::uint64_t>(cfm::limits::kMaxFlowMillilitresPerSecond),
              static_cast<std::uint64_t>(1000000000));
  CT_CHECK_EQ(static_cast<std::uint64_t>(cfm::limits::kMaxTimestampMilliseconds),
              static_cast<std::uint64_t>(4102444800000));
  CT_CHECK_EQ(static_cast<std::uint64_t>(cfm::limits::kMaxWindowMilliseconds),
              static_cast<std::uint64_t>(86400000));
  CT_CHECK_EQ(static_cast<std::uint64_t>(cfm::limits::kMaxIdentifierBytes),
              static_cast<std::uint64_t>(128));
  CT_CHECK_EQ(static_cast<std::uint64_t>(cfm::limits::kMaxObservationPerScope),
              static_cast<std::uint64_t>(512));
}
