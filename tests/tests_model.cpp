// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Model-adjacent but model-free proofs: the version boundary, the configured
// table bounds and the identity entry points every model object is built on.
// The model semantics themselves are proved by the model test cases.

#include "test_framework.hpp"

#include <cstddef>
#include <string>
#include <string_view>

#include "dccp/cooling_failure_manager/enums.hpp"
#include "dccp/cooling_failure_manager/limits.hpp"
#include "dccp/cooling_failure_manager/result.hpp"
#include "dccp/cooling_failure_manager/strong_id.hpp"
#include "dccp/cooling_failure_manager/version.hpp"

namespace {

using namespace dccp::cooling_failure_manager;

}  // namespace

CT_TEST(test_model_free_version_boundary) {
  CT_CHECK_EQ(std::string(version_string()), std::string("1.0.1"));
  CT_CHECK_EQ(std::string(component_id()), std::string("dccp-cooling-failure-manager/1.0.1"));
  CT_CHECK(!systems_boundary().empty());
#ifdef COOLING_FAILURE_MANAGER_CMAKE_VERSION
  CT_CHECK_EQ(std::string(version_string()), std::string(COOLING_FAILURE_MANAGER_CMAKE_VERSION));
#else
  ct_test::report_note(
      "COOLING_FAILURE_MANAGER_CMAKE_VERSION is not defined; the CMake cross-check did not run");
#endif
}

CT_TEST(test_model_free_table_bounds) {
  // Each configured bound must admit the whole enumeration it bounds, otherwise
  // a valid classification could not be represented at all.
  CT_CHECK(limits::kMaxFailureClassCount >= failure_class_count());
  CT_CHECK(limits::kMaxRecoveryGateCount >= recovery_gate_count());
  CT_CHECK(limits::kMaxRestrictionCount >= restriction_kind_count());
  // A per-scope bound is only meaningful when it is inside the global bound.
  const std::size_t per_scope_bound = limits::kMaxObservationPerScope;
  std::size_t global_bound = limits::kMaxObservationCount;
  CT_CHECK(per_scope_bound <= global_bound);
  // A single scope can never confirm more classes than the taxonomy has.
  CT_CHECK(limits::kMaxConfirmedClassesPerScope <= failure_class_count());
  // The dwell and hysteresis windows a scope declares are bounded by the
  // longest window the library accepts, which is itself inside the timeline.
  std::int64_t longest_window = limits::kMaxWindowMilliseconds;
  CT_CHECK(longest_window > 0);
  const std::int64_t latest_timestamp = limits::kMaxTimestampMilliseconds;
  CT_CHECK(latest_timestamp > longest_window);
}

CT_TEST(test_model_free_identity_entry_points) {
  const auto scope = ScopeId::parse("model-free-scope");
  CT_REQUIRE(scope.has_value());
  CT_REQUIRE(scope.has_value());
  const auto scope_text = scope.value().value();
  CT_CHECK_EQ(scope_text, std::string_view("model-free-scope"));
  CT_CHECK(!scope.value().empty());

  const auto rejected = ScopeId::parse("-not-an-identifier");
  CT_CHECK(!rejected.has_value());
  CT_CHECK_EQ(static_cast<int>(rejected.error().code()), static_cast<int>(ErrorCode::MalformedIdentifier));

  const auto plan = PlanId::parse("plan-7");
  CT_REQUIRE(plan.has_value());
  CT_CHECK(plan.value() != PlanId());
}
