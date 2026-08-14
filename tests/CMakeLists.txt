set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../third_party/googletest"
                 "${CMAKE_CURRENT_BINARY_DIR}/googletest" EXCLUDE_FROM_ALL)

function(heyaki_add_runtime_test test_name target_name labels)
  if(HEYAKI_SANITIZER STREQUAL "none")
    add_test(NAME ${test_name} COMMAND ${target_name} ${ARGN})
  else()
    add_test(
      NAME ${test_name}
      COMMAND "${CMAKE_COMMAND}"
        "-DHEYAKI_TEST_PROGRAM=$<TARGET_FILE:${target_name}>"
        "-DHEYAKI_TEST_ARGUMENTS=${ARGN}"
        "-DHEYAKI_REQUIRE_SANITIZER_RUNTIME=${HEYAKI_REQUIRE_SANITIZER_RUNTIME}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/sanitizer/RunSanitizedTest.cmake")
    set_tests_properties(${test_name} PROPERTIES
      SKIP_REGULAR_EXPRESSION "HEYAKI_SANITIZER_UNSUPPORTED:")
  endif()
  set_tests_properties(${test_name} PROPERTIES LABELS "${labels}")
endfunction()

add_executable(heyaki_unit_tests unit/version_test.cpp)
target_link_libraries(heyaki_unit_tests PRIVATE heyaki::core GTest::gtest_main)
target_compile_definitions(heyaki_unit_tests PRIVATE
  "HEYAKI_TEST_EXPECT_APPS=$<BOOL:${HEYAKI_BUILD_APPS}>"
  "HEYAKI_TEST_EXPECT_ZSTD=0")
heyaki_configure_target(heyaki_unit_tests)
heyaki_add_runtime_test(heyaki_unit heyaki_unit_tests "unit")

add_executable(heyaki_public_headers_compile compile/public_headers.cpp)
target_link_libraries(heyaki_public_headers_compile PRIVATE heyaki::core)
heyaki_configure_target(heyaki_public_headers_compile)
heyaki_add_runtime_test(heyaki_public_headers heyaki_public_headers_compile "protocol;security")

add_test(
  NAME heyaki_public_header_boundary
  COMMAND "${CMAKE_COMMAND}"
    "-DHEYAKI_PUBLIC_INCLUDE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/../include"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/compile/CheckPublicHeaders.cmake")
set_tests_properties(heyaki_public_header_boundary PROPERTIES LABELS "protocol;security")

add_executable(heyaki_module_linkage integration/module_linkage.cpp)
target_link_libraries(heyaki_module_linkage PRIVATE
  heyaki::core
  heyaki::profile
  heyaki::client
  heyaki::services
  heyaki::transport_webrtc)
heyaki_configure_target(heyaki_module_linkage)
heyaki_add_runtime_test(heyaki_module_linkage heyaki_module_linkage "integration")

add_executable(heyaki_fuzz_smoke fuzz/fuzz_smoke.cpp)
target_link_libraries(heyaki_fuzz_smoke PRIVATE heyaki::core)
heyaki_configure_target(heyaki_fuzz_smoke)
heyaki_add_runtime_test(
  heyaki_fuzz_smoke heyaki_fuzz_smoke "fuzz;security" "${HEYAKI_FUZZ_CORPUS_DIR}")
add_custom_target(heyaki-fuzz-smoke
  COMMAND "${CMAKE_CTEST_COMMAND}" --output-on-failure -L fuzz -C "$<CONFIG>"
  DEPENDS heyaki_fuzz_smoke
  USES_TERMINAL)

add_executable(heyaki_performance_smoke performance/build_info_benchmark.cpp)
target_link_libraries(heyaki_performance_smoke PRIVATE heyaki::core)
heyaki_configure_target(heyaki_performance_smoke)
heyaki_add_runtime_test(
  heyaki_performance_smoke heyaki_performance_smoke "performance")

if(HEYAKI_BUILD_APPS)
  heyaki_add_runtime_test(heyaki_tui_version heyaki-tui "tui" --version)
endif()

add_test(
  NAME heyaki_network_harness
  COMMAND "${HEYAKI_BASH_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/network/run_harness.sh")
set_tests_properties(heyaki_network_harness PROPERTIES
  LABELS "network"
  SKIP_RETURN_CODE 77)

add_test(
  NAME heyaki_dependency_lock_crlf
  COMMAND "${CMAKE_COMMAND}"
    "-DHEYAKI_FETCH_SCRIPT=${CMAKE_CURRENT_SOURCE_DIR}/../scripts/fetch_third_party.sh"
    "-DHEYAKI_DEPENDENCY_LOCK=${CMAKE_CURRENT_SOURCE_DIR}/../third_party/dependencies.lock"
    "-DHEYAKI_TEST_WORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/dependency-lock-work"
    "-DHEYAKI_BASH_EXECUTABLE=${HEYAKI_BASH_EXECUTABLE}"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/supply_chain/CheckCrlfDependencyLock.cmake")
set_tests_properties(heyaki_dependency_lock_crlf PROPERTIES LABELS "security")

find_program(HEYAKI_OPENSSL_EXECUTABLE NAMES openssl)
find_program(HEYAKI_SQLITE3_EXECUTABLE NAMES sqlite3)
if(HEYAKI_OPENSSL_EXECUTABLE AND HEYAKI_SQLITE3_EXECUTABLE)
  set(fixture_manifest "${HEYAKI_TEST_STATE_DIR}/fixtures/manifest.txt")
  add_custom_command(
    OUTPUT "${fixture_manifest}"
    COMMAND "${CMAKE_COMMAND}"
      "-DHEYAKI_FIXTURE_DIR=${HEYAKI_TEST_STATE_DIR}/fixtures"
      "-DHEYAKI_OPENSSL_EXECUTABLE=${HEYAKI_OPENSSL_EXECUTABLE}"
      "-DHEYAKI_SQLITE3_EXECUTABLE=${HEYAKI_SQLITE3_EXECUTABLE}"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/GenerateFixtures.cmake"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/GenerateFixtures.cmake"
    VERBATIM)
  add_custom_target(heyaki-test-fixtures DEPENDS "${fixture_manifest}")
  add_test(
    NAME heyaki_fixture_generation
    COMMAND "${CMAKE_COMMAND}" --build "${CMAKE_BINARY_DIR}"
      --target heyaki-test-fixtures --config "$<CONFIG>")
else()
  add_custom_target(heyaki-test-fixtures
    COMMAND "${CMAKE_COMMAND}" -E echo
      "OpenSSL and sqlite3 are required to generate Heyaki test fixtures"
    COMMAND "${CMAKE_COMMAND}" -E false)
  add_test(NAME heyaki_fixture_generation
    COMMAND "${CMAKE_COMMAND}" -E echo
      "SKIP: OpenSSL and sqlite3 are required for test fixture generation")
  set_tests_properties(heyaki_fixture_generation PROPERTIES
    SKIP_REGULAR_EXPRESSION "SKIP:")
endif()
set_tests_properties(heyaki_fixture_generation PROPERTIES LABELS "integration;security")

add_test(
  NAME heyaki_installed_consumer
  COMMAND "${CMAKE_COMMAND}"
    "-DHEYAKI_ROOT_BINARY_DIR=${CMAKE_BINARY_DIR}"
    "-DHEYAKI_CONSUMER_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/consumer"
    "-DHEYAKI_CONSUMER_WORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/consumer-work"
    "-DHEYAKI_CONFIG=$<CONFIG>"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/consumer/RunConsumerTest.cmake")
set_tests_properties(heyaki_installed_consumer PROPERTIES LABELS "integration")

if(WIN32)
  set_tests_properties(heyaki_public_headers
    PROPERTIES LABELS "protocol;security;windows")
  set_tests_properties(heyaki_installed_consumer
    PROPERTIES LABELS "integration;windows")
endif()
