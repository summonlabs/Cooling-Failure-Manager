# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.
#
# Configures, builds and runs the out-of-tree downstream consumer against an
# already installed prefix. It never uses a timeout of any kind.

if(NOT DEFINED CONSUMER_SOURCE_DIR)
  message(FATAL_ERROR "CONSUMER_SOURCE_DIR is required")
endif()
if(NOT DEFINED CONSUMER_BINARY_DIR)
  message(FATAL_ERROR "CONSUMER_BINARY_DIR is required")
endif()
if(NOT DEFINED CONSUMER_PREFIX)
  message(FATAL_ERROR "CONSUMER_PREFIX is required")
endif()

file(REMOVE_RECURSE "${CONSUMER_BINARY_DIR}")

# The consumer is built the way the library under test was built: the same
# configuration (a Release consumer does not link against a Debug library), the
# same generator and compiler, and the sanitizer flags when the library has
# them. The per-configuration link flags come last on the link line, so that is
# where a flag such as /INCREMENTAL:NO has to go to take effect.
if(NOT DEFINED CONSUMER_CONFIG OR CONSUMER_CONFIG STREQUAL "")
  set(CONSUMER_CONFIG Release)
endif()
set(configure_command "${CMAKE_COMMAND}"
    -S "${CONSUMER_SOURCE_DIR}"
    -B "${CONSUMER_BINARY_DIR}"
    "-DCMAKE_BUILD_TYPE=${CONSUMER_CONFIG}"
    "-DCMAKE_PREFIX_PATH=${CONSUMER_PREFIX}")
if(DEFINED CONSUMER_GENERATOR AND NOT CONSUMER_GENERATOR STREQUAL "")
  list(APPEND configure_command -G "${CONSUMER_GENERATOR}")
endif()
if(DEFINED CONSUMER_CXX_COMPILER AND NOT CONSUMER_CXX_COMPILER STREQUAL "")
  list(APPEND configure_command "-DCMAKE_CXX_COMPILER=${CONSUMER_CXX_COMPILER}")
endif()
if(DEFINED CONSUMER_CXX_FLAGS AND NOT CONSUMER_CXX_FLAGS STREQUAL "")
  list(APPEND configure_command "-DCMAKE_CXX_FLAGS_INIT=${CONSUMER_CXX_FLAGS}")
endif()
if(DEFINED CONSUMER_LINK_FLAGS AND NOT CONSUMER_LINK_FLAGS STREQUAL "")
  string(TOUPPER "${CONSUMER_CONFIG}" consumer_config_upper)
  list(APPEND configure_command
       "-DCMAKE_EXE_LINKER_FLAGS_${consumer_config_upper}=${CONSUMER_LINK_FLAGS}")
endif()

execute_process(
  COMMAND ${configure_command}
  RESULT_VARIABLE configure_result
  OUTPUT_VARIABLE configure_output
  ERROR_VARIABLE configure_error)
if(NOT configure_result EQUAL 0)
  message(FATAL_ERROR "downstream configure failed:\n${configure_output}\n${configure_error}")
endif()

execute_process(
  COMMAND "${CMAKE_COMMAND}" --build "${CONSUMER_BINARY_DIR}" --config "${CONSUMER_CONFIG}"
  RESULT_VARIABLE build_result
  OUTPUT_VARIABLE build_output
  ERROR_VARIABLE build_error)
if(NOT build_result EQUAL 0)
  message(FATAL_ERROR "downstream build failed:\n${build_output}\n${build_error}")
endif()

# A consumer built by a single-configuration generator puts its executable
# directly in the binary directory; a multi-configuration generator puts it in a
# per-configuration subdirectory. Both are the same build, so the executable is
# located rather than assumed, and a consumer that built nothing is reported as
# such instead of being run from a path that does not exist.
set(consumer_executable "")
# The platform suffix is derived from the host rather than from
# CMAKE_EXECUTABLE_SUFFIX, which is empty in script mode because no language was
# enabled in this process.
if(WIN32)
  set(consumer_suffix ".exe")
else()
  set(consumer_suffix "")
endif()
foreach(candidate
    "${CONSUMER_BINARY_DIR}/cooling_failure_manager_downstream_consumer${consumer_suffix}"
    "${CONSUMER_BINARY_DIR}/Release/cooling_failure_manager_downstream_consumer${consumer_suffix}"
    "${CONSUMER_BINARY_DIR}/Debug/cooling_failure_manager_downstream_consumer${consumer_suffix}"
    "${CONSUMER_BINARY_DIR}/RelWithDebInfo/cooling_failure_manager_downstream_consumer${consumer_suffix}"
    "${CONSUMER_BINARY_DIR}/MinSizeRel/cooling_failure_manager_downstream_consumer${consumer_suffix}")
  if(EXISTS "${candidate}")
    set(consumer_executable "${candidate}")
    break()
  endif()
endforeach()
if(consumer_executable STREQUAL "")
  message(FATAL_ERROR
    "the downstream consumer built no executable under ${CONSUMER_BINARY_DIR}")
endif()

execute_process(
  COMMAND "${consumer_executable}"
  WORKING_DIRECTORY "${CONSUMER_BINARY_DIR}"
  RESULT_VARIABLE run_result
  OUTPUT_VARIABLE run_output
  ERROR_VARIABLE run_error)
if(NOT run_result EQUAL 0)
  message(FATAL_ERROR "downstream run failed (${run_result}):\n${run_output}\n${run_error}")
endif()

message(STATUS "downstream consumer ok (${consumer_executable}): ${run_output}")
