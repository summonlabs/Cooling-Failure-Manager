// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/cooling_failure_manager/version.hpp"

namespace dccp::cooling_failure_manager {

std::string_view version_string() noexcept { return "1.0.0"; }

std::string_view systems_boundary() noexcept {
  return "generation-bound cooling-failure classification, response-plan and recovery gate "
         "authority over synthetic cooling evidence; no actuation, no flow measurement, no "
         "thermal-safety policy, no workload placement";
}

std::string_view component_id() noexcept { return "dccp-cooling-failure-manager/1.0.0"; }

}  // namespace dccp::cooling_failure_manager
