// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_COOLING_FAILURE_MANAGER_VERSION_HPP
#define DCCP_COOLING_FAILURE_MANAGER_VERSION_HPP

#include <cstdint>
#include <string_view>

namespace dccp::cooling_failure_manager {

/// Library version. Kept in sync with the CMake project version; the test suite
/// compares the compiled-in value against the CMake value so the two cannot
/// drift apart silently.
inline constexpr std::uint32_t kVersionMajor = 1;
inline constexpr std::uint32_t kVersionMinor = 0;
inline constexpr std::uint32_t kVersionPatch = 1;

/// "1.0.1"
std::string_view version_string() noexcept;

/// The systems boundary this library implements, in one line.
///
/// "generation-bound cooling-failure classification, response-plan and recovery
///  gate authority over synthetic cooling evidence; no actuation, no flow
///  measurement, no thermal-safety policy, no workload placement"
std::string_view systems_boundary() noexcept;

/// Machine-readable component name used in provenance records.
///
/// "dccp-cooling-failure-manager/1.0.1"
std::string_view component_id() noexcept;

}  // namespace dccp::cooling_failure_manager

#endif  // DCCP_COOLING_FAILURE_MANAGER_VERSION_HPP
