// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Internal file-system surface used by the durable store. Not installed.
//
// This header exists so that the store implementation depends on one narrow
// set of primitives and so that the platform-specific details stay in
// file_ops.cpp. Every function here reports durability explicitly and never
// claims durability it did not establish.

#ifndef DCCP_COOLING_FAILURE_MANAGER_SRC_STORE_FILES_HPP
#define DCCP_COOLING_FAILURE_MANAGER_SRC_STORE_FILES_HPP

#include "file_ops.hpp"

namespace dccp::cooling_failure_manager::internal {

/// Names of the fixed entries of a store root.
inline constexpr const char* kLockFileName = "lock";
inline constexpr const char* kFloorFileName = "floor";
inline constexpr const char* kManifestFileName = "manifest";
inline constexpr const char* kPreviousManifestFileName = "manifest.prev";
inline constexpr const char* kGenerationsDirectoryName = "generations";
inline constexpr const char* kStagingDirectoryName = "staging";
inline constexpr const char* kIdempotencyDirectoryName = "idem";

}  // namespace dccp::cooling_failure_manager::internal

#endif  // DCCP_COOLING_FAILURE_MANAGER_SRC_STORE_FILES_HPP
