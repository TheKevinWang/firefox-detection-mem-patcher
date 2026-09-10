# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.20)
project(
  firefox_detection_mem_patcher
  VERSION 0.1.0
  DESCRIPTION "Windows proof of concept for exact-build in-memory Firefox detection patches"
  LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(livepatch_core
  src/core.cpp
)
target_include_directories(livepatch_core PUBLIC include)
target_compile_definitions(livepatch_core PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(livepatch_core PRIVATE /W4 /permissive-)
target_link_libraries(livepatch_core PUBLIC bcrypt psapi)

add_executable(firefox-detection-mem-patcher src/main.cpp)
target_compile_definitions(
  firefox-detection-mem-patcher
  PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    FIREFOX_DETECTION_MEM_PATCHER_VERSION="${PROJECT_VERSION}"
)
target_compile_options(firefox-detection-mem-patcher PRIVATE /W4 /permissive-)
target_link_libraries(firefox-detection-mem-patcher PRIVATE livepatch_core)

enable_testing()
add_executable(patcher-tests tests/core_tests.cpp)
target_compile_definitions(patcher-tests PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(patcher-tests PRIVATE /W4 /permissive-)
target_link_libraries(patcher-tests PRIVATE livepatch_core)
add_test(NAME patcher-tests COMMAND patcher-tests)
