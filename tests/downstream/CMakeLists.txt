# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.
#
# An independent out-of-tree consumer of the installed package. It deliberately
# uses only the exported target and the public headers: nothing from this
# repository's source tree is on its include path or its link line.

cmake_minimum_required(VERSION 3.20)

project(cooling_failure_manager_downstream_consumer
        VERSION 1.0.1
        DESCRIPTION "Out-of-tree consumer of the installed Cooling Failure Manager package"
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(cooling_failure_manager 1.0 REQUIRED)

add_executable(cooling_failure_manager_downstream_consumer main.cpp)
target_link_libraries(cooling_failure_manager_downstream_consumer
  PRIVATE dccp::cooling_failure_manager)
