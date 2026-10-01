# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.
#
# Cooling Failure Manager - DCCP boundary 54 (Cooling Infrastructure Control).
#
# The primary product surface is the library target cooling_failure_manager,
# exported as dccp::cooling_failure_manager. The inspection CLI, examples, tests
# and benchmarks are optional; only the library and the CLI are installed.

cmake_minimum_required(VERSION 3.20)

# Keep in sync with include/dccp/cooling_failure_manager/version.hpp; the test
# suite compares this value against the compiled-in library version.
project(cooling_failure_manager
        VERSION 1.0.1
        DESCRIPTION "Generation-bound cooling failure classification, response and recovery authority"
        HOMEPAGE_URL "https://github.com/summonlabs/Cooling-Failure-Manager"
        LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(COOLING_FAILURE_MANAGER_BUILD_TESTS "Build the Cooling Failure Manager test suite" ON)
option(COOLING_FAILURE_MANAGER_BUILD_TOOLS "Build the cfmctl inspection tool" ON)
option(COOLING_FAILURE_MANAGER_BUILD_EXAMPLES "Build the Cooling Failure Manager examples" ON)
option(COOLING_FAILURE_MANAGER_BUILD_BENCHMARKS "Build the Cooling Failure Manager benchmarks" ON)
option(COOLING_FAILURE_MANAGER_WARNINGS_AS_ERRORS "Treat first-party warnings as errors" ON)
option(COOLING_FAILURE_MANAGER_ENABLE_ASAN "Build with AddressSanitizer" OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Warnings and sanitizers
# ---------------------------------------------------------------------------

add_library(cooling_failure_manager_warnings INTERFACE)
add_library(dccp::cooling_failure_manager_warnings ALIAS cooling_failure_manager_warnings)

if(MSVC)
  target_compile_options(cooling_failure_manager_warnings INTERFACE
    /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc /MP)
  if(COOLING_FAILURE_MANAGER_WARNINGS_AS_ERRORS)
    target_compile_options(cooling_failure_manager_warnings INTERFACE /WX)
  endif()
else()
  target_compile_options(cooling_failure_manager_warnings INTERFACE
    -Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor -Wcast-align -Wunused
    -Woverloaded-virtual -Wnull-dereference -Wdouble-promotion -Wformat=2)
  if(COOLING_FAILURE_MANAGER_WARNINGS_AS_ERRORS)
    target_compile_options(cooling_failure_manager_warnings INTERFACE -Werror)
  endif()
endif()

add_library(cooling_failure_manager_sanitizers INTERFACE)
if(COOLING_FAILURE_MANAGER_ENABLE_ASAN)
  if(MSVC)
    # /Zi is required alongside /fsanitize=address: without debug information
    # the compiler emits C5072 on every translation unit, which a
    # warnings-as-errors build correctly refuses, and an ASan report could not
    # name the line it came from. /fsanitize=address is a compiler-driver
    # option; passing it to link.exe only produces LNK4044, so the link side
    # asks for /DEBUG instead.
    target_compile_options(cooling_failure_manager_sanitizers INTERFACE /fsanitize=address /Zi)
    target_link_options(cooling_failure_manager_sanitizers INTERFACE /DEBUG)
  else()
    target_compile_options(cooling_failure_manager_sanitizers INTERFACE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(cooling_failure_manager_sanitizers INTERFACE -fsanitize=address -fno-omit-frame-pointer)
  endif()
endif()

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------

add_library(cooling_failure_manager
  src/version.cpp
  src/result.cpp
  src/text.cpp
  src/digest.cpp
  src/strong_id.cpp
  src/enums.cpp
  src/model.cpp
  src/evidence.cpp
  src/classify.cpp
  src/decision.cpp
  src/recovery.cpp
  src/canonical.cpp
  src/file_ops.cpp
  src/store_internal.cpp
  src/store_impl.cpp)
add_library(dccp::cooling_failure_manager ALIAS cooling_failure_manager)

target_compile_features(cooling_failure_manager PUBLIC cxx_std_20)
target_include_directories(cooling_failure_manager
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(cooling_failure_manager
  PRIVATE
    $<BUILD_INTERFACE:cooling_failure_manager_warnings>
    $<BUILD_INTERFACE:cooling_failure_manager_sanitizers>)
set_target_properties(cooling_failure_manager PROPERTIES
  CXX_EXTENSIONS OFF
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  POSITION_INDEPENDENT_CODE ON
  EXPORT_NAME cooling_failure_manager)

# ---------------------------------------------------------------------------
# Inspection tool
# ---------------------------------------------------------------------------

if(COOLING_FAILURE_MANAGER_BUILD_TOOLS)
  add_executable(cfmctl tools/cfmctl/main.cpp)
  target_link_libraries(cfmctl PRIVATE dccp::cooling_failure_manager cooling_failure_manager_warnings cooling_failure_manager_sanitizers)
  set_target_properties(cfmctl PROPERTIES CXX_EXTENSIONS OFF)
endif()

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------

if(COOLING_FAILURE_MANAGER_BUILD_EXAMPLES)
  foreach(example_name IN ITEMS
      chiller_plant_loss
      cdu_leak_response
      shared_loop_attribution
      durable_failure_journal
      unresolved_attempt_recovery)
    add_executable(cooling_failure_manager_example_${example_name} examples/${example_name}.cpp)
    target_link_libraries(cooling_failure_manager_example_${example_name}
      PRIVATE dccp::cooling_failure_manager cooling_failure_manager_warnings cooling_failure_manager_sanitizers)
    set_target_properties(cooling_failure_manager_example_${example_name} PROPERTIES CXX_EXTENSIONS OFF)
  endforeach()
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if(COOLING_FAILURE_MANAGER_BUILD_TESTS)
  enable_testing()

  add_library(cooling_failure_manager_test_support STATIC
    tests/test_main.cpp
    tests/child_process.cpp)
  target_link_libraries(cooling_failure_manager_test_support
    PUBLIC dccp::cooling_failure_manager cooling_failure_manager_warnings cooling_failure_manager_sanitizers)
  target_include_directories(cooling_failure_manager_test_support
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tests
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_compile_definitions(cooling_failure_manager_test_support
    PUBLIC COOLING_FAILURE_MANAGER_CMAKE_VERSION="${PROJECT_VERSION}")
  set_target_properties(cooling_failure_manager_test_support PROPERTIES CXX_EXTENSIONS OFF)

  add_executable(cooling_failure_manager_tests
    tests/tests_foundation.cpp
    tests/tests_evidence.cpp
    tests/tests_classify.cpp
    tests/tests_decision.cpp
    tests/tests_recovery.cpp
    tests/tests_model.cpp
    tests/tests_canonical.cpp
    tests/tests_store.cpp
    tests/tests_store_recovery.cpp
    tests/tests_idempotency.cpp
    tests/tests_replay_durability.cpp
    tests/tests_property.cpp
    tests/tests_adversarial.cpp
    tests/tests_multiprocess.cpp
    tests/tests_integration.cpp
    tests/tests_cli.cpp)
  target_link_libraries(cooling_failure_manager_tests PRIVATE cooling_failure_manager_test_support)
  target_include_directories(cooling_failure_manager_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  set_target_properties(cooling_failure_manager_tests PROPERTIES CXX_EXTENSIONS OFF)

  if(COOLING_FAILURE_MANAGER_BUILD_TOOLS)
    target_compile_definitions(cooling_failure_manager_tests
      PRIVATE COOLING_FAILURE_MANAGER_CLI_PATH="$<TARGET_FILE:cfmctl>")
    add_dependencies(cooling_failure_manager_tests cfmctl)
  endif()

  add_test(NAME cooling_failure_manager_tests COMMAND cooling_failure_manager_tests)
  set_tests_properties(cooling_failure_manager_tests PROPERTIES
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

  # The consumer is built against an installed prefix, never against the build
  # tree, so the fixture installs first. That is the only way the test can prove
  # the exported package works: a consumer that reached into the build tree would
  # pass even if the install rules were broken.
  set(COOLING_FAILURE_MANAGER_PACKAGE_PREFIX ${CMAKE_BINARY_DIR}/package-prefix)
  add_test(NAME cooling_failure_manager_install_package
    COMMAND ${CMAKE_COMMAND} --install ${CMAKE_BINARY_DIR}
            --prefix ${COOLING_FAILURE_MANAGER_PACKAGE_PREFIX}
            --config $<CONFIG>)
  set_tests_properties(cooling_failure_manager_install_package PROPERTIES
    FIXTURES_SETUP cooling_failure_manager_package)

  add_test(NAME cooling_failure_manager_downstream_consumer
    COMMAND ${CMAKE_COMMAND}
      -DCONSUMER_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/tests/downstream
      -DCONSUMER_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}/downstream-build
      -DCONSUMER_PREFIX=${COOLING_FAILURE_MANAGER_PACKAGE_PREFIX}
      -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/run_downstream_consumer.cmake)
  set_tests_properties(cooling_failure_manager_downstream_consumer PROPERTIES
    FIXTURES_REQUIRED cooling_failure_manager_package)
endif()

# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

if(COOLING_FAILURE_MANAGER_BUILD_BENCHMARKS)
  add_executable(cooling_failure_manager_benchmarks benchmarks/benchmarks.cpp)
  target_link_libraries(cooling_failure_manager_benchmarks
    PRIVATE dccp::cooling_failure_manager cooling_failure_manager_warnings cooling_failure_manager_sanitizers)
  set_target_properties(cooling_failure_manager_benchmarks PROPERTIES CXX_EXTENSIONS OFF)
endif()

# ---------------------------------------------------------------------------
# Install and export
# ---------------------------------------------------------------------------

install(TARGETS cooling_failure_manager
  EXPORT cooling_failure_managerTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(COOLING_FAILURE_MANAGER_BUILD_TOOLS)
  install(TARGETS cfmctl RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

set(COOLING_FAILURE_MANAGER_CMAKE_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/cooling_failure_manager)

install(EXPORT cooling_failure_managerTargets
  FILE cooling_failure_managerTargets.cmake
  NAMESPACE dccp::
  DESTINATION ${COOLING_FAILURE_MANAGER_CMAKE_INSTALL_DIR})

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cooling_failure_managerConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/cooling_failure_managerConfig.cmake
  INSTALL_DESTINATION ${COOLING_FAILURE_MANAGER_CMAKE_INSTALL_DIR})

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/cooling_failure_managerConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/cooling_failure_managerConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/cooling_failure_managerConfigVersion.cmake
  DESTINATION ${COOLING_FAILURE_MANAGER_CMAKE_INSTALL_DIR})

install(FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/README.md
  ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE
  ${CMAKE_CURRENT_SOURCE_DIR}/NOTICE
  DESTINATION ${CMAKE_INSTALL_DOCDIR})
