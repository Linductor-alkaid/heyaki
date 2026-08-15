set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../third_party/googletest"
                 "${CMAKE_CURRENT_BINARY_DIR}/googletest" EXCLUDE_FROM_ALL)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

get_target_property(heyaki_sodium_interface_definitions
  heyaki_sodium INTERFACE_COMPILE_DEFINITIONS)
if(NOT "SODIUM_STATIC" IN_LIST heyaki_sodium_interface_definitions)
  message(FATAL_ERROR
    "Vendored static libsodium must propagate SODIUM_STATIC to consumers")
endif()

set(ABSL_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ABSL_BUILD_TEST_HELPERS OFF CACHE BOOL "" FORCE)
set(ABSL_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
set(ABSL_PROPAGATE_CXX_STD ON CACHE BOOL "" FORCE)
set(ABSL_MSVC_STATIC_RUNTIME OFF CACHE BOOL "" FORCE)
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../third_party/abseil-cpp"
                 "${CMAKE_CURRENT_BINARY_DIR}/abseil-cpp" EXCLUDE_FROM_ALL)

set(protobuf_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_CONFORMANCE OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(protobuf_INSTALL OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_PROTOBUF_BINARIES ON CACHE BOOL "" FORCE)
set(protobuf_BUILD_PROTOC_BINARIES ON CACHE BOOL "" FORCE)
set(protobuf_BUILD_LIBUPB ON CACHE BOOL "" FORCE)
set(protobuf_WITH_ZLIB OFF CACHE BOOL "" FORCE)
set(protobuf_LOCAL_DEPENDENCIES_ONLY ON CACHE BOOL "" FORCE)
set(protobuf_MSVC_STATIC_RUNTIME OFF CACHE BOOL "" FORCE)
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../third_party/protobuf"
                 "${CMAKE_CURRENT_BINARY_DIR}/protobuf" EXCLUDE_FROM_ALL)
include("${CMAKE_CURRENT_SOURCE_DIR}/../third_party/protobuf/cmake/protobuf-generate.cmake")

foreach(heyaki_protobuf_abi_target IN ITEMS
    absl_cord libprotobuf-lite libprotobuf libprotoc protoc)
  get_target_property(heyaki_protobuf_abi_cxx_standard
    ${heyaki_protobuf_abi_target} CXX_STANDARD)
  if(NOT heyaki_protobuf_abi_cxx_standard EQUAL 20)
    message(FATAL_ERROR
      "${heyaki_protobuf_abi_target} must use C++20 to keep Abseil drop-in types ABI-compatible; "
      "got CXX_STANDARD=${heyaki_protobuf_abi_cxx_standard}")
  endif()
endforeach()
if(MSVC AND (ABSL_MSVC_STATIC_RUNTIME OR protobuf_MSVC_STATIC_RUNTIME))
  message(FATAL_ERROR
    "Pinned Abseil and Protobuf targets must use the dynamic MSVC runtime")
endif()

set(HEYAKI_PROTO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../proto")
set(HEYAKI_PROTO_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated-proto")
file(MAKE_DIRECTORY "${HEYAKI_PROTO_GENERATED_DIR}")
file(GLOB_RECURSE HEYAKI_PROTO_FILES CONFIGURE_DEPENDS "${HEYAKI_PROTO_ROOT}/*.proto")
list(SORT HEYAKI_PROTO_FILES)
protobuf_generate(
  LANGUAGE cpp
  OUT_VAR HEYAKI_PROTO_GENERATED_SOURCES
  PROTOS ${HEYAKI_PROTO_FILES}
  IMPORT_DIRS "${HEYAKI_PROTO_ROOT}"
  PROTOC_OUT_DIR "${HEYAKI_PROTO_GENERATED_DIR}"
  PROTOC_EXE protobuf::protoc)
add_library(heyaki_protocol_lite STATIC ${HEYAKI_PROTO_GENERATED_SOURCES})
target_compile_features(heyaki_protocol_lite PUBLIC cxx_std_20)
target_include_directories(heyaki_protocol_lite SYSTEM PUBLIC
  "${HEYAKI_PROTO_GENERATED_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/protobuf/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/abseil-cpp")
target_link_libraries(heyaki_protocol_lite PUBLIC protobuf::libprotobuf-lite)
if(NOT HEYAKI_SANITIZER STREQUAL "none")
  if(HEYAKI_SANITIZER STREQUAL "address")
    set(heyaki_protocol_sanitizer_flag -fsanitize=address)
  elseif(HEYAKI_SANITIZER STREQUAL "undefined")
    set(heyaki_protocol_sanitizer_flag -fsanitize=undefined)
  elseif(HEYAKI_SANITIZER STREQUAL "thread")
    set(heyaki_protocol_sanitizer_flag -fsanitize=thread)
  endif()
  target_compile_options(heyaki_protocol_lite PRIVATE
    "${heyaki_protocol_sanitizer_flag}"
    -fno-omit-frame-pointer)
  target_link_options(heyaki_protocol_lite PUBLIC
    "${heyaki_protocol_sanitizer_flag}"
    -fno-omit-frame-pointer)
endif()

set(HEYAKI_M1_GOLDEN_VECTOR_FILE
  "${CMAKE_CURRENT_SOURCE_DIR}/vectors/m1-golden-vectors.json")
file(READ "${HEYAKI_M1_GOLDEN_VECTOR_FILE}" HEYAKI_M1_GOLDEN_VECTOR_JSON)
set(HEYAKI_M3A_GOLDEN_VECTOR_FILE
  "${CMAKE_CURRENT_SOURCE_DIR}/vectors/m3a-lan-golden-vectors.json")
file(READ "${HEYAKI_M3A_GOLDEN_VECTOR_FILE}" HEYAKI_M3A_GOLDEN_VECTOR_JSON)

function(heyaki_read_golden_json output_variable)
  string(JSON value ERROR_VARIABLE json_error GET
    "${HEYAKI_M1_GOLDEN_VECTOR_JSON}" ${ARGN})
  if(json_error)
    message(FATAL_ERROR
      "Cannot read ${HEYAKI_M1_GOLDEN_VECTOR_FILE} at '${ARGN}': ${json_error}")
  endif()
  set(${output_variable} "${value}" PARENT_SCOPE)
endfunction()

function(heyaki_read_m3a_golden_json output_variable)
  string(JSON value ERROR_VARIABLE json_error GET
    "${HEYAKI_M3A_GOLDEN_VECTOR_JSON}" ${ARGN})
  if(json_error)
    message(FATAL_ERROR
      "Cannot read ${HEYAKI_M3A_GOLDEN_VECTOR_FILE} at '${ARGN}': ${json_error}")
  endif()
  set(${output_variable} "${value}" PARENT_SCOPE)
endfunction()

heyaki_read_golden_json(M1_PROTOCOL_MAJOR protocol major)
heyaki_read_golden_json(M1_PROTOCOL_MINOR protocol minor)
heyaki_read_golden_json(M1_IDENTITY_PUBLIC_KEY_HEX device_id identity_public_key_hex)
heyaki_read_golden_json(M1_DEVICE_DIGEST_HEX device_id sha256_hex)
heyaki_read_golden_json(M1_DEVICE_ID_TEXT device_id text)
heyaki_read_golden_json(M1_CANONICAL_DOMAIN canonical_offer domain)
foreach(field_number RANGE 1 10)
  heyaki_read_golden_json(M1_CANONICAL_FIELD_${field_number}_HEX
    canonical_offer field_${field_number}_hex)
endforeach()
heyaki_read_golden_json(M1_CANONICAL_HEX canonical_offer canonical_hex)
heyaki_read_golden_json(M1_ED25519_SEED_HEX ed25519_canonical_offer seed_hex)
heyaki_read_golden_json(M1_ED25519_PUBLIC_KEY_HEX ed25519_canonical_offer public_key_hex)
heyaki_read_golden_json(M1_ED25519_MESSAGE_HEX ed25519_canonical_offer message_hex)
heyaki_read_golden_json(M1_ED25519_SIGNATURE_HEX ed25519_canonical_offer signature_hex)
heyaki_read_golden_json(M1_SIGNALING_TRANSCRIPT_DOMAIN signaling_transcript domain)
heyaki_read_golden_json(M1_CANONICAL_ANSWER_HEX signaling_transcript canonical_answer_hex)
heyaki_read_golden_json(M1_SIGNALING_TRANSCRIPT_SHA256_HEX signaling_transcript sha256_hex)
heyaki_read_golden_json(M1_PROTOBUF_ENVELOPE_HEX protobuf_message_envelope bytes_hex)
heyaki_read_golden_json(M1_FRAME_HEX frame bytes_hex)
heyaki_read_m3a_golden_json(M3A_PROTOCOL_MAJOR protocol major)
heyaki_read_m3a_golden_json(M3A_PROTOCOL_MINOR protocol minor)
heyaki_read_m3a_golden_json(M3A_IPV4_GROUP discovery ipv4_group)
heyaki_read_m3a_golden_json(M3A_IPV6_GROUP discovery ipv6_group)
heyaki_read_m3a_golden_json(M3A_UDP_PORT discovery udp_port)
heyaki_read_m3a_golden_json(M3A_HOP_LIMIT discovery hop_limit)
heyaki_read_m3a_golden_json(M3A_DATAGRAM_MAGIC_HEX discovery datagram_magic_hex)
heyaki_read_m3a_golden_json(M3A_DATAGRAM_ENVELOPE_VERSION discovery datagram_envelope_version)
heyaki_read_m3a_golden_json(M3A_PRESENCE_TYPE discovery presence_type)
heyaki_read_m3a_golden_json(M3A_MAX_DATAGRAM_BYTES discovery max_datagram_bytes)
heyaki_read_m3a_golden_json(M3A_ED25519_PUBLIC_KEY_HEX signing_key public_key_hex)
heyaki_read_m3a_golden_json(M3A_PRESENCE_DOMAIN canonical_lan_presence domain)
foreach(field_number RANGE 1 11)
  heyaki_read_m3a_golden_json(M3A_PRESENCE_FIELD_${field_number}_HEX
    canonical_lan_presence field_${field_number}_hex)
endforeach()
heyaki_read_m3a_golden_json(M3A_PRESENCE_CANONICAL_HEX canonical_lan_presence canonical_hex)
heyaki_read_m3a_golden_json(M3A_PRESENCE_SIGNATURE_HEX canonical_lan_presence signature_hex)
heyaki_read_m3a_golden_json(M3A_HELLO_DOMAIN canonical_lan_hello domain)
foreach(field_number RANGE 1 16)
  heyaki_read_m3a_golden_json(M3A_HELLO_FIELD_${field_number}_HEX
    canonical_lan_hello field_${field_number}_hex)
endforeach()
heyaki_read_m3a_golden_json(M3A_HELLO_CANONICAL_HEX canonical_lan_hello canonical_hex)
heyaki_read_m3a_golden_json(M3A_HELLO_SIGNATURE_HEX canonical_lan_hello signature_hex)

set(HEYAKI_TEST_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${HEYAKI_TEST_GENERATED_DIR}")
configure_file(
  vectors/m1_golden_vectors.hpp.in
  "${HEYAKI_TEST_GENERATED_DIR}/m1_golden_vectors.hpp"
  @ONLY)
configure_file(
  vectors/m3a_lan_golden_vectors.hpp.in
  "${HEYAKI_TEST_GENERATED_DIR}/m3a_lan_golden_vectors.hpp"
  @ONLY)

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

add_executable(heyaki_unit_tests
  unit/contracts_test.cpp
  unit/golden_vectors_test.cpp
  unit/signing_test.cpp
  unit/version_test.cpp
  unit/wire_test.cpp)
target_link_libraries(heyaki_unit_tests PRIVATE heyaki::core GTest::gtest_main OpenSSL::Crypto)
target_include_directories(heyaki_unit_tests PRIVATE
  "${HEYAKI_TEST_GENERATED_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/unit")
target_compile_definitions(heyaki_unit_tests PRIVATE
  "HEYAKI_TEST_EXPECT_APPS=$<BOOL:${HEYAKI_BUILD_APPS}>"
  "HEYAKI_TEST_EXPECT_ZSTD=0")
heyaki_configure_target(heyaki_unit_tests)
heyaki_add_runtime_test(heyaki_unit heyaki_unit_tests "unit;protocol;security")

add_executable(heyaki_m2_profile_tests unit/m2_profile_test.cpp)
target_link_libraries(heyaki_m2_profile_tests PRIVATE
  heyaki::profile
  heyaki::sqlite
  executor::executor
  GTest::gtest_main)
target_compile_definitions(heyaki_m2_profile_tests PRIVATE
  "HEYAKI_M2_TEST_STATE_DIR=\"${HEYAKI_TEST_STATE_DIR}\""
  "HEYAKI_M2_PROFILE_V1_FIXTURE=\"${CMAKE_CURRENT_SOURCE_DIR}/fixtures/profile_store_v1.sql\"")
heyaki_configure_target(heyaki_m2_profile_tests)
heyaki_enable_executor_exception_adapter_source(unit/m2_profile_test.cpp)
heyaki_add_runtime_test(
  heyaki_m2_profile heyaki_m2_profile_tests "unit;profile;security")

add_library(heyaki_profile_fault_injection STATIC
  ../src/profile/password.cpp
  ../src/profile/profile_store.cpp
  ../src/profile/secret_backend.cpp)
target_compile_definitions(heyaki_profile_fault_injection PRIVATE
  HEYAKI_PROFILE_FAULT_INJECTION=1)
target_link_libraries(heyaki_profile_fault_injection
  PUBLIC heyaki::core
  PRIVATE heyaki::sodium heyaki::sqlite)
if(WIN32)
  target_link_libraries(heyaki_profile_fault_injection PRIVATE crypt32)
elseif(CMAKE_DL_LIBS)
  target_link_libraries(heyaki_profile_fault_injection PRIVATE ${CMAKE_DL_LIBS})
endif()
heyaki_configure_target(heyaki_profile_fault_injection)

add_executable(heyaki_m2_profile_crash_probe profile/profile_crash_probe.cpp)
target_link_libraries(heyaki_m2_profile_crash_probe PRIVATE
  heyaki_profile_fault_injection
  heyaki::sqlite)
heyaki_configure_target(heyaki_m2_profile_crash_probe)
add_test(
  NAME heyaki_profile_crash_recovery
  COMMAND "${CMAKE_COMMAND}"
    "-DHEYAKI_PROFILE_CRASH_PROBE=$<TARGET_FILE:heyaki_m2_profile_crash_probe>"
    "-DHEYAKI_PROFILE_CRASH_STATE_DIR=${HEYAKI_TEST_STATE_DIR}/profile-crash"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/profile/RunProfileCrashTest.cmake")
set_tests_properties(heyaki_profile_crash_recovery PROPERTIES
  LABELS "integration;profile;security")
if(NOT HEYAKI_SANITIZER STREQUAL "none" AND
   NOT HEYAKI_REQUIRE_SANITIZER_RUNTIME)
  set_tests_properties(heyaki_profile_crash_recovery PROPERTIES
    SKIP_REGULAR_EXPRESSION
      "LeakSanitizer does not work under ptrace;ThreadSanitizer: unexpected memory mapping")
endif()

add_executable(heyaki_m2_runtime_tests unit/m2_runtime_test.cpp)
target_link_libraries(heyaki_m2_runtime_tests PRIVATE
  heyaki::client
  executor::executor
  GTest::gtest_main)
heyaki_configure_target(heyaki_m2_runtime_tests)
heyaki_enable_executor_exception_adapter_source(unit/m2_runtime_test.cpp)
heyaki_add_runtime_test(
  heyaki_m2_runtime heyaki_m2_runtime_tests "unit;runtime;concurrency")

set(heyaki_public_header_sources)
foreach(public_header IN ITEMS
    error identity ids limits operation password profile_store protocol runtime secret_backend
    security signing time version wire)
  set(header_source
    "${HEYAKI_TEST_GENERATED_DIR}/${public_header}_header_standalone.cpp")
  file(GENERATE OUTPUT "${header_source}"
    CONTENT "#include <heyaki/${public_header}.hpp>\n")
  list(APPEND heyaki_public_header_sources "${header_source}")
endforeach()
add_executable(heyaki_public_headers_compile
  compile/public_headers.cpp
  ${heyaki_public_header_sources})
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

add_library(heyaki_fuzz_harness OBJECT fuzz/protocol_fuzz.cpp)
target_link_libraries(heyaki_fuzz_harness PRIVATE heyaki::core heyaki_protocol_lite)
target_include_directories(heyaki_fuzz_harness PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/fuzz")
heyaki_configure_target(heyaki_fuzz_harness)

add_executable(heyaki_fuzz_smoke
  fuzz/fuzz_smoke.cpp
  $<TARGET_OBJECTS:heyaki_fuzz_harness>)
target_link_libraries(heyaki_fuzz_smoke PRIVATE heyaki::core heyaki_protocol_lite)
target_include_directories(heyaki_fuzz_smoke PRIVATE
  "${HEYAKI_TEST_GENERATED_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/fuzz")
heyaki_configure_target(heyaki_fuzz_smoke)
heyaki_add_runtime_test(
  heyaki_fuzz_smoke heyaki_fuzz_smoke "fuzz;security" "${HEYAKI_FUZZ_CORPUS_DIR}")
add_custom_target(heyaki-fuzz-smoke
  COMMAND "${CMAKE_CTEST_COMMAND}" --output-on-failure -L fuzz -C "$<CONFIG>"
  DEPENDS heyaki_fuzz_smoke
  USES_TERMINAL)

if(HEYAKI_BUILD_FUZZERS)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "HEYAKI_BUILD_FUZZERS requires Clang libFuzzer support")
  endif()

  add_executable(heyaki_frame_parser_fuzzer
    fuzz/parser_fuzzer_entry.cpp
    $<TARGET_OBJECTS:heyaki_fuzz_harness>)
  target_link_libraries(heyaki_frame_parser_fuzzer PRIVATE heyaki::core heyaki_protocol_lite)
  target_include_directories(heyaki_frame_parser_fuzzer PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/fuzz")
  target_compile_options(heyaki_frame_parser_fuzzer PRIVATE -fsanitize=fuzzer)
  target_link_options(heyaki_frame_parser_fuzzer PRIVATE -fsanitize=fuzzer)
  heyaki_configure_target(heyaki_frame_parser_fuzzer)

  add_executable(heyaki_protocol_state_fuzzer
    fuzz/state_machine_fuzzer_entry.cpp
    $<TARGET_OBJECTS:heyaki_fuzz_harness>)
  target_link_libraries(heyaki_protocol_state_fuzzer PRIVATE heyaki::core heyaki_protocol_lite)
  target_include_directories(heyaki_protocol_state_fuzzer PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/fuzz")
  target_compile_options(heyaki_protocol_state_fuzzer PRIVATE -fsanitize=fuzzer)
  target_link_options(heyaki_protocol_state_fuzzer PRIVATE -fsanitize=fuzzer)
  heyaki_configure_target(heyaki_protocol_state_fuzzer)

  add_executable(heyaki_protobuf_parser_fuzzer
    fuzz/protobuf_fuzzer_entry.cpp
    $<TARGET_OBJECTS:heyaki_fuzz_harness>)
  target_link_libraries(heyaki_protobuf_parser_fuzzer PRIVATE
    heyaki::core
    heyaki_protocol_lite)
  target_include_directories(heyaki_protobuf_parser_fuzzer PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/fuzz")
  target_compile_options(heyaki_protobuf_parser_fuzzer PRIVATE -fsanitize=fuzzer)
  target_link_options(heyaki_protobuf_parser_fuzzer PRIVATE -fsanitize=fuzzer)
  heyaki_configure_target(heyaki_protobuf_parser_fuzzer)
endif()

add_test(
  NAME heyaki_protocol_sources
  COMMAND "${CMAKE_COMMAND}"
    "-DHEYAKI_PROTO_DIR=${CMAKE_CURRENT_SOURCE_DIR}/../proto"
    "-DHEYAKI_WIRE_DOCUMENT=${CMAKE_CURRENT_SOURCE_DIR}/../docs/design/heyaki-wire-protocol.md"
    "-DHEYAKI_THREAT_MODEL=${CMAKE_CURRENT_SOURCE_DIR}/../docs/security/threat-model.md"
    "-DHEYAKI_GOLDEN_VECTOR_FILE=${HEYAKI_M1_GOLDEN_VECTOR_FILE}"
    "-DHEYAKI_M3A_GOLDEN_VECTOR_FILE=${HEYAKI_M3A_GOLDEN_VECTOR_FILE}"
    "-DHEYAKI_PROTOCOL_MAJOR=${HEYAKI_PROTOCOL_VERSION_MAJOR}"
    "-DHEYAKI_PROTOCOL_MINOR=${HEYAKI_PROTOCOL_VERSION_MINOR}"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/protocol/CheckProtocolSources.cmake")
set_tests_properties(heyaki_protocol_sources PROPERTIES LABELS "protocol;security")

add_executable(heyaki_protobuf_conformance protocol/protobuf_conformance_test.cpp)
target_link_libraries(heyaki_protobuf_conformance PRIVATE
  heyaki_protocol_lite
  GTest::gtest_main)
target_include_directories(heyaki_protobuf_conformance PRIVATE
  "${HEYAKI_TEST_GENERATED_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/unit")
heyaki_configure_target(heyaki_protobuf_conformance)
heyaki_add_runtime_test(
  heyaki_protobuf_conformance heyaki_protobuf_conformance "protocol;security;fuzz")

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

add_test(
  NAME heyaki_msvc_sqlite_generation
  COMMAND "${CMAKE_COMMAND}"
    "-DHEYAKI_VENDORED_RUNTIME_MODULE=${CMAKE_CURRENT_SOURCE_DIR}/../cmake/HeyakiVendoredRuntime.cmake"
    "-DHEYAKI_TEST_WORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/msvc-sqlite-generation-work"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/build/CheckMsvcSqliteGeneration.cmake")
set_tests_properties(heyaki_msvc_sqlite_generation PROPERTIES LABELS "build;windows")

add_test(
  NAME heyaki_supply_chain_inventory
  COMMAND "${CMAKE_COMMAND}"
    "-DHEYAKI_SBOM_FILE=${HEYAKI_SBOM_FILE}"
    "-DHEYAKI_LICENSE_MANIFEST_FILE=${HEYAKI_LICENSE_MANIFEST_FILE}"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/supply_chain/CheckGeneratedSupplyChain.cmake")
set_tests_properties(heyaki_supply_chain_inventory PROPERTIES LABELS "security")

find_program(HEYAKI_GIT_EXECUTABLE NAMES git REQUIRED)
add_test(
  NAME heyaki_transitive_dependency_lock
  COMMAND "${CMAKE_COMMAND}"
    "-DHEYAKI_GIT_EXECUTABLE=${HEYAKI_GIT_EXECUTABLE}"
    "-DHEYAKI_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/.."
    "-DHEYAKI_TRANSITIVE_DEPENDENCY_LOCK=${CMAKE_CURRENT_SOURCE_DIR}/../third_party/transitive-dependencies.lock"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/supply_chain/CheckTransitiveDependencyLock.cmake")
set_tests_properties(heyaki_transitive_dependency_lock PROPERTIES LABELS "security")

add_test(
  NAME heyaki_libdatachannel_compatibility_contract
  COMMAND "${CMAKE_COMMAND}"
    "-DHEYAKI_LIBDATACHANNEL_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/../third_party/libdatachannel"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/compatibility/CheckLibdatachannelBaseline.cmake")
set_tests_properties(heyaki_libdatachannel_compatibility_contract PROPERTIES
  LABELS "network;security")

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
