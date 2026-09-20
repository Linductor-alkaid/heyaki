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
set(HEYAKI_M10_GOLDEN_VECTOR_FILE
  "${CMAKE_CURRENT_SOURCE_DIR}/vectors/m10-golden-vectors.json")
file(READ "${HEYAKI_M10_GOLDEN_VECTOR_FILE}" HEYAKI_M10_GOLDEN_VECTOR_JSON)

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

function(heyaki_read_m10_golden_json output_variable)
  string(JSON value ERROR_VARIABLE json_error GET
    "${HEYAKI_M10_GOLDEN_VECTOR_JSON}" ${ARGN})
  if(json_error)
    message(FATAL_ERROR
      "Cannot read ${HEYAKI_M10_GOLDEN_VECTOR_FILE} at '${ARGN}': ${json_error}")
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

# M10-01 gateway golden vectors: frozen at configure time from
# tests/vectors/m10-golden-vectors.json (see docs/design/heyaki-wire-protocol.md §7).
heyaki_read_m10_golden_json(M10_PROTOCOL_MAJOR protocol major)
heyaki_read_m10_golden_json(M10_PROTOCOL_MINOR protocol minor)
heyaki_read_m10_golden_json(M10_GATEWAY_CONNECT_HEX gateway_connect bytes_hex)
heyaki_read_m10_golden_json(M10_GATEWAY_CONNECT_NO_PROFILE_HEX
  gateway_connect_no_profile bytes_hex)
heyaki_read_m10_golden_json(M10_STREAM_OPEN_ID_HEX stream_open stream_id_hex)
heyaki_read_m10_golden_json(M10_STREAM_OPEN_WINDOW_BYTES stream_open receive_window_bytes)
heyaki_read_m10_golden_json(M10_STREAM_OPEN_WINDOW_FRAMES
  stream_open receive_window_frames)
heyaki_read_m10_golden_json(M10_STREAM_OPEN_PLAIN_HEX stream_open plain_hex)
heyaki_read_m10_golden_json(M10_STREAM_OPEN_GATEWAY_HEX stream_open gateway_hex)
heyaki_read_m10_golden_json(M10_PRELUDE_CONNECTED_HEX prelude_connected_hex)

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
configure_file(
  vectors/m10_golden_vectors.hpp.in
  "${HEYAKI_TEST_GENERATED_DIR}/m10_golden_vectors.hpp"
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
  unit/m5_framing_test.cpp
  unit/golden_vectors_test.cpp
  unit/lan_protocol_test.cpp
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

add_executable(heyaki_m2_profile_tests
  unit/m2_profile_test.cpp
  unit/m3b_relay_profile_test.cpp)
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

# M9-08 file-service crash matrix: a second test-only compile of the file
# store with named _Exit(86) fault points (same pattern as the ProfileStore
# crash suite). The probe links this variant ahead of heyaki::client so its
# file_store object wins symbol resolution; production code carries no-ops.
add_library(heyaki_file_fault_injection STATIC
  ../src/client/file_store.cpp)
target_compile_definitions(heyaki_file_fault_injection PRIVATE
  HEYAKI_FILE_FAULT_INJECTION=1)
target_link_libraries(heyaki_file_fault_injection
  PUBLIC heyaki::core
  PRIVATE heyaki::blake3)
heyaki_configure_target(heyaki_file_fault_injection)

add_executable(heyaki_m9_file_crash_probe file/file_crash_probe.cpp)
target_link_libraries(heyaki_m9_file_crash_probe PRIVATE
  heyaki_file_fault_injection
  heyaki::client
  heyaki::core
  heyaki::blake3
  executor::executor
  GTest::gtest)
target_include_directories(heyaki_m9_file_crash_probe PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client"
  "${CMAKE_CURRENT_SOURCE_DIR}/unit")
heyaki_configure_target(heyaki_m9_file_crash_probe)
add_test(
  NAME heyaki_m9_file_crash_recovery
  COMMAND "${CMAKE_COMMAND}"
    "-DHEYAKI_FILE_CRASH_PROBE=$<TARGET_FILE:heyaki_m9_file_crash_probe>"
    "-DHEYAKI_FILE_CRASH_STATE_DIR=${HEYAKI_TEST_STATE_DIR}/file-crash"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/file/RunFileCrashTest.cmake")
set_tests_properties(heyaki_m9_file_crash_recovery PROPERTIES
  LABELS "integration;file;m9;reliability")
if(NOT HEYAKI_SANITIZER STREQUAL "none" AND
   NOT HEYAKI_REQUIRE_SANITIZER_RUNTIME)
  set_tests_properties(heyaki_m9_file_crash_recovery PROPERTIES
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

add_executable(heyaki_m3a_lan_tests unit/m3a_lan_test.cpp)
heyaki_enable_executor_exception_adapter_source(unit/m3a_lan_test.cpp)
target_link_libraries(heyaki_m3a_lan_tests PRIVATE
  heyaki::client
  executor::executor
  GTest::gtest_main
  OpenSSL::SSL)
heyaki_target_use_pinned_boost_asio(heyaki_m3a_lan_tests)
heyaki_configure_target(heyaki_m3a_lan_tests)
target_compile_definitions(heyaki_m3a_lan_tests PRIVATE
  "HEYAKI_M3A_TEST_STATE_DIR=\"${HEYAKI_TEST_STATE_DIR}\"")
heyaki_add_runtime_test(
  heyaki_m3a_lan heyaki_m3a_lan_tests "unit;lan;security")
set_tests_properties(heyaki_m3a_lan PROPERTIES RESOURCE_LOCK heyaki_m3a_profile_state)

add_executable(heyaki_m4_signaling_tests unit/m4_signaling_test.cpp)
target_link_libraries(heyaki_m4_signaling_tests PRIVATE
  heyaki::client
  GTest::gtest_main)
target_include_directories(heyaki_m4_signaling_tests PRIVATE
  "${HEYAKI_TEST_GENERATED_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/unit"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src")
heyaki_configure_target(heyaki_m4_signaling_tests)
heyaki_add_runtime_test(
  heyaki_m4_signaling heyaki_m4_signaling_tests "unit;signaling;security")

add_executable(heyaki_m4_session_hello_tests unit/m4_session_hello_test.cpp)
target_link_libraries(heyaki_m4_session_hello_tests PRIVATE
  heyaki::core
  heyaki_protocol_lite
  GTest::gtest_main)
heyaki_configure_target(heyaki_m4_session_hello_tests)
heyaki_add_runtime_test(
  heyaki_m4_session_hello heyaki_m4_session_hello_tests
  "unit;session;security;protocol")

add_executable(heyaki_m4_session_restart_tests unit/m4_session_restart_test.cpp)
target_link_libraries(heyaki_m4_session_restart_tests PRIVATE
  heyaki::core
  GTest::gtest_main)
heyaki_configure_target(heyaki_m4_session_restart_tests)
heyaki_add_runtime_test(
  heyaki_m4_session_restart heyaki_m4_session_restart_tests
  "unit;session;security;protocol")

add_executable(heyaki_m4_relay_cycle_repro unit/m4_relay_cycle_repro_test.cpp)
heyaki_enable_executor_exception_adapter_source(unit/m4_relay_cycle_repro_test.cpp)
target_link_libraries(heyaki_m4_relay_cycle_repro PRIVATE
  heyaki::relay
  executor::executor
  GTest::gtest_main
  OpenSSL::SSL OpenSSL::Crypto)
heyaki_target_use_pinned_boost_beast(heyaki_m4_relay_cycle_repro)
target_include_directories(heyaki_m4_relay_cycle_repro PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/relay"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src")
heyaki_configure_target(heyaki_m4_relay_cycle_repro)
target_compile_definitions(heyaki_m4_relay_cycle_repro PRIVATE
  "HEYAKI_M4_REPRO_STATE_DIR=\"${HEYAKI_TEST_STATE_DIR}/repro\"")

add_executable(heyaki_m4_topology_matrix_tests unit/m4_topology_matrix_test.cpp)
heyaki_enable_executor_exception_adapter_source(unit/m4_topology_matrix_test.cpp)
target_link_libraries(heyaki_m4_topology_matrix_tests PRIVATE
  heyaki::client
  executor::executor
  GTest::gtest_main
  OpenSSL::SSL)
heyaki_target_use_pinned_boost_asio(heyaki_m4_topology_matrix_tests)
heyaki_configure_target(heyaki_m4_topology_matrix_tests)
target_compile_definitions(heyaki_m4_topology_matrix_tests PRIVATE
  "HEYAKI_M4_TOPOLOGY_TEST_STATE_DIR=\"${HEYAKI_TEST_STATE_DIR}\"")
heyaki_add_runtime_test(
  heyaki_m4_topology_matrix heyaki_m4_topology_matrix_tests
  "unit;session;transport;lan")
set_tests_properties(heyaki_m4_topology_matrix PROPERTIES
  RESOURCE_LOCK heyaki_m3a_profile_state
  TIMEOUT 300)

add_executable(heyaki_m4_shutdown_matrix_tests unit/m4_shutdown_matrix_test.cpp)
heyaki_enable_executor_exception_adapter_source(unit/m4_shutdown_matrix_test.cpp)
target_link_libraries(heyaki_m4_shutdown_matrix_tests PRIVATE
  heyaki::client
  executor::executor
  GTest::gtest_main
  OpenSSL::SSL)
heyaki_target_use_pinned_boost_asio(heyaki_m4_shutdown_matrix_tests)
heyaki_configure_target(heyaki_m4_shutdown_matrix_tests)
target_compile_definitions(heyaki_m4_shutdown_matrix_tests PRIVATE
  "HEYAKI_M4_SHUTDOWN_TEST_STATE_DIR=\"${HEYAKI_TEST_STATE_DIR}\"")
heyaki_add_runtime_test(
  heyaki_m4_shutdown_matrix heyaki_m4_shutdown_matrix_tests
  "unit;session;transport;lan;reliability")
set_tests_properties(heyaki_m4_shutdown_matrix PROPERTIES
  RESOURCE_LOCK heyaki_m3a_profile_state
  TIMEOUT 600)

add_executable(heyaki_m4_session_restart_e2e_tests unit/m4_session_restart_e2e_test.cpp)
heyaki_enable_executor_exception_adapter_source(unit/m4_session_restart_e2e_test.cpp)
target_link_libraries(heyaki_m4_session_restart_e2e_tests PRIVATE
  heyaki::client
  executor::executor
  GTest::gtest_main
  OpenSSL::SSL)
heyaki_target_use_pinned_boost_asio(heyaki_m4_session_restart_e2e_tests)
heyaki_configure_target(heyaki_m4_session_restart_e2e_tests)
target_compile_definitions(heyaki_m4_session_restart_e2e_tests PRIVATE
  "HEYAKI_M4_RESTART_TEST_STATE_DIR=\"${HEYAKI_TEST_STATE_DIR}\"")
heyaki_add_runtime_test(
  heyaki_m4_session_restart_e2e heyaki_m4_session_restart_e2e_tests
  "unit;session;transport;lan;security")
set_tests_properties(heyaki_m4_session_restart_e2e PROPERTIES
  RESOURCE_LOCK heyaki_m3a_profile_state
  TIMEOUT 300)

add_executable(heyaki_m5_session_tests
  unit/m5_channels_test.cpp
  unit/m5_session_test.cpp)
target_link_libraries(heyaki_m5_session_tests PRIVATE
  heyaki::client
  heyaki::core
  GTest::gtest_main)
target_include_directories(heyaki_m5_session_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client"
  "${CMAKE_CURRENT_SOURCE_DIR}/unit")
heyaki_configure_target(heyaki_m5_session_tests)
heyaki_enable_executor_exception_adapter_source(unit/m5_session_test.cpp)
heyaki_add_runtime_test(
  heyaki_m5_session heyaki_m5_session_tests
  "unit;session;security;protocol;concurrency")

add_executable(heyaki_m6_service_tests
  unit/m6_message_test.cpp
  unit/m6_rpc_test.cpp)
target_link_libraries(heyaki_m6_service_tests PRIVATE
  heyaki::client
  heyaki::core
  executor::executor
  GTest::gtest_main)
target_include_directories(heyaki_m6_service_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client"
  "${CMAKE_CURRENT_SOURCE_DIR}/unit")
heyaki_configure_target(heyaki_m6_service_tests)
heyaki_add_runtime_test(
  heyaki_m6_service heyaki_m6_service_tests
  "unit;session;security;protocol;concurrency;m6")

add_executable(heyaki_m9_metrics_tests unit/m9_metrics_test.cpp)
heyaki_enable_executor_exception_adapter_source(unit/m9_metrics_test.cpp)
target_link_libraries(heyaki_m9_metrics_tests PRIVATE
  heyaki::client
  executor::executor
  GTest::gtest_main
  OpenSSL::SSL)
heyaki_target_use_pinned_boost_asio(heyaki_m9_metrics_tests)
heyaki_configure_target(heyaki_m9_metrics_tests)
target_compile_definitions(heyaki_m9_metrics_tests PRIVATE
  "HEYAKI_M9_METRICS_TEST_STATE_DIR=\"${HEYAKI_TEST_STATE_DIR}\"")
heyaki_add_runtime_test(
  heyaki_m9_metrics heyaki_m9_metrics_tests "unit;metrics;m9;lan")
set_tests_properties(heyaki_m9_metrics PROPERTIES
  RESOURCE_LOCK heyaki_m3a_profile_state
  TIMEOUT 180)

add_executable(heyaki_m9_relay_observability_tests
  unit/m9_relay_observability_test.cpp)
heyaki_enable_executor_exception_adapter_source(unit/m9_relay_observability_test.cpp)
target_link_libraries(heyaki_m9_relay_observability_tests PRIVATE
  heyaki::relay
  executor::executor
  heyaki::sqlite
  GTest::gtest_main
  OpenSSL::SSL
  OpenSSL::Crypto)
heyaki_target_use_pinned_boost_beast(heyaki_m9_relay_observability_tests)
target_include_directories(heyaki_m9_relay_observability_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client")
heyaki_configure_target(heyaki_m9_relay_observability_tests)
target_compile_definitions(heyaki_m9_relay_observability_tests PRIVATE
  "HEYAKI_M9_RELAY_TEST_STATE_DIR=\"${HEYAKI_TEST_STATE_DIR}\"")
heyaki_add_runtime_test(
  heyaki_m9_relay_observability heyaki_m9_relay_observability_tests
  "unit;relay;metrics;m9;observability")
set_tests_properties(heyaki_m9_relay_observability PROPERTIES
  RESOURCE_LOCK heyaki_m3a_profile_state
  TIMEOUT 180)

add_executable(heyaki_m9_correlation_tests unit/m9_correlation_test.cpp)
heyaki_enable_executor_exception_adapter_source(unit/m9_correlation_test.cpp)
target_link_libraries(heyaki_m9_correlation_tests PRIVATE
  heyaki::client
  executor::executor
  GTest::gtest_main
  OpenSSL::SSL)
heyaki_target_use_pinned_boost_asio(heyaki_m9_correlation_tests)
target_include_directories(heyaki_m9_correlation_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client"
  "${CMAKE_CURRENT_SOURCE_DIR}/unit")
heyaki_configure_target(heyaki_m9_correlation_tests)
heyaki_add_runtime_test(
  heyaki_m9_correlation heyaki_m9_correlation_tests
  "unit;metrics;m9;correlation;session")
set_tests_properties(heyaki_m9_correlation PROPERTIES
  RESOURCE_LOCK heyaki_m3a_profile_state
  TIMEOUT 180)

add_executable(heyaki_m9_slo_rules_tests unit/m9_slo_rules_test.cpp)
heyaki_enable_executor_exception_adapter_source(unit/m9_slo_rules_test.cpp)
target_link_libraries(heyaki_m9_slo_rules_tests PRIVATE
  heyaki::client
  heyaki::relay
  executor::executor
  GTest::gtest_main)
target_compile_definitions(heyaki_m9_slo_rules_tests PRIVATE
  "HEYAKI_M9_OBSERVABILITY_DIR=\"${PROJECT_SOURCE_DIR}/deploy/observability\""
  "HEYAKI_M9_RUNBOOK_FILE=\"${PROJECT_SOURCE_DIR}/docs/operations/runbook.md\"")
heyaki_configure_target(heyaki_m9_slo_rules_tests)
heyaki_add_runtime_test(
  heyaki_m9_slo_rules heyaki_m9_slo_rules_tests
  "unit;metrics;m9;observability;slo")
set_tests_properties(heyaki_m9_slo_rules PROPERTIES
  TIMEOUT 60)

add_executable(heyaki_m9_parameter_freeze_tests unit/m9_parameter_freeze_test.cpp)
target_link_libraries(heyaki_m9_parameter_freeze_tests PRIVATE
  heyaki::client
  heyaki::relay
  heyaki::core
  heyaki::blake3
  executor::executor
  GTest::gtest_main)
target_include_directories(heyaki_m9_parameter_freeze_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client"
  "${CMAKE_CURRENT_SOURCE_DIR}/unit")
heyaki_target_use_pinned_boost_beast(heyaki_m9_parameter_freeze_tests)
heyaki_configure_target(heyaki_m9_parameter_freeze_tests)
heyaki_add_runtime_test(
  heyaki_m9_parameter_freeze heyaki_m9_parameter_freeze_tests
  "unit;config;m9;parameters;freezing")
set_tests_properties(heyaki_m9_parameter_freeze PROPERTIES
  TIMEOUT 120)

# M9-16: user-facing documentation examples are extracted from the docs and
# compiled/executed, so a stale or non-compiling sample fails CI instead of
# rotting. Extraction runs at configure time; the doc files are registered as
# configure dependencies so editing them re-runs the extraction.
set(HEYAKI_DOCS_EXAMPLE_DIR "${CMAKE_CURRENT_BINARY_DIR}/docs-examples")
set(HEYAKI_DOCS_SOURCES
  "${PROJECT_SOURCE_DIR}/docs/getting-started.md"
  "${PROJECT_SOURCE_DIR}/docs/configuration.md"
  "${PROJECT_SOURCE_DIR}/docs/deployment.md"
  "${PROJECT_SOURCE_DIR}/docs/api.md"
  "${PROJECT_SOURCE_DIR}/docs/troubleshooting.md"
  "${PROJECT_SOURCE_DIR}/docs/client-library.md")
execute_process(
  COMMAND "${CMAKE_COMMAND}"
    "-DHEYAKI_DOCS_LIST=${HEYAKI_DOCS_SOURCES}"
    "-DHEYAKI_OUTPUT_DIR=${HEYAKI_DOCS_EXAMPLE_DIR}"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/docs/extract_doc_examples.cmake"
  RESULT_VARIABLE heyaki_docs_extraction_result)
if(NOT heyaki_docs_extraction_result EQUAL 0)
  message(FATAL_ERROR "Doc example extraction failed")
endif()
include("${HEYAKI_DOCS_EXAMPLE_DIR}/examples-manifest.cmake")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  ${HEYAKI_DOCS_SOURCES})

foreach(heyaki_doc_slug IN LISTS HEYAKI_DOC_CPP_EXAMPLES)
  add_executable(heyaki-doc-example-${heyaki_doc_slug}
    "${HEYAKI_DOCS_EXAMPLE_DIR}/${heyaki_doc_slug}.cpp")
  target_link_libraries(heyaki-doc-example-${heyaki_doc_slug} PRIVATE
    heyaki::client
    executor::executor)
  heyaki_configure_target(heyaki-doc-example-${heyaki_doc_slug})
  list(APPEND HEYAKI_DOC_CPP_BINARIES
    "$<TARGET_FILE:heyaki-doc-example-${heyaki_doc_slug}>")
endforeach()
foreach(heyaki_doc_node_example IN ITEMS "node-lifecycle" "sdk-first-program")
  if(heyaki_doc_node_example IN_LIST HEYAKI_DOC_CPP_EXAMPLES)
    heyaki_enable_executor_exception_adapter_source(
      "${HEYAKI_DOCS_EXAMPLE_DIR}/${heyaki_doc_node_example}.cpp")
  endif()
endforeach()

add_executable(heyaki-doc-relay-config-check docs/relay_config_doc_check.cpp)
target_link_libraries(heyaki-doc-relay-config-check PRIVATE
  heyaki::relay
  executor::executor)
heyaki_configure_target(heyaki-doc-relay-config-check)

set(HEYAKI_DOC_RELAY_CONFIG_FILES "")
foreach(heyaki_doc_slug IN LISTS HEYAKI_DOC_RELAY_CONFIGS)
  list(APPEND HEYAKI_DOC_RELAY_CONFIG_FILES
    "${HEYAKI_DOCS_EXAMPLE_DIR}/${heyaki_doc_slug}.conf")
endforeach()

add_test(
  NAME heyaki_m9_docs_examples
  COMMAND "${CMAKE_COMMAND}"
    "-DHEYAKI_DOC_CPP_BINARIES=${HEYAKI_DOC_CPP_BINARIES}"
    "-DHEYAKI_DOC_RELAY_CONFIGS=${HEYAKI_DOC_RELAY_CONFIG_FILES}"
    "-DHEYAKI_DOC_CONFIG_CHECK=$<TARGET_FILE:heyaki-doc-relay-config-check>"
    "-DHEYAKI_DOC_WORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/docs-examples-work"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/docs/run_doc_examples.cmake")
set_tests_properties(heyaki_m9_docs_examples PROPERTIES
  LABELS "unit;docs;m9"
  TIMEOUT 300)

add_executable(heyaki_m9_compat_tests unit/m9_compat_test.cpp)
target_link_libraries(heyaki_m9_compat_tests PRIVATE
  heyaki::client
  heyaki::relay
  heyaki::core
  heyaki::sqlite
  executor::executor
  GTest::gtest_main)
target_include_directories(heyaki_m9_compat_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client"
  "${CMAKE_CURRENT_SOURCE_DIR}/unit")
heyaki_configure_target(heyaki_m9_compat_tests)
target_compile_definitions(heyaki_m9_compat_tests PRIVATE
  "HEYAKI_M9_COMPAT_TEST_STATE_DIR=\"${HEYAKI_TEST_STATE_DIR}\"")
heyaki_add_runtime_test(
  heyaki_m9_compat heyaki_m9_compat_tests
  "unit;protocol;relay;m9;compatibility")
set_tests_properties(heyaki_m9_compat PROPERTIES
  TIMEOUT 120)

add_executable(heyaki_m9_security_regression_tests
  unit/m9_security_regression_test.cpp)
target_link_libraries(heyaki_m9_security_regression_tests PRIVATE
  heyaki::client
  heyaki::core
  GTest::gtest_main)
heyaki_configure_target(heyaki_m9_security_regression_tests)
heyaki_add_runtime_test(
  heyaki_m9_security_regression heyaki_m9_security_regression_tests
  "unit;security;m9;regression")
set_tests_properties(heyaki_m9_security_regression PROPERTIES
  TIMEOUT 60)

# M10-01/M10-02: protocol 1.3 gateway change-sheet surfaces — GatewayConnect
# grammar/codec/prelude/refusal mapping, capability negotiation, golden
# vectors, and the ByteStream gateway send/receive gates over the loopback
# session harness.
add_executable(heyaki_m10_protocol_tests unit/m10_protocol_test.cpp)
target_link_libraries(heyaki_m10_protocol_tests PRIVATE
  heyaki::client
  heyaki::core
  GTest::gtest_main)
target_include_directories(heyaki_m10_protocol_tests PRIVATE
  "${HEYAKI_TEST_GENERATED_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client"
  "${CMAKE_CURRENT_SOURCE_DIR}/unit")
heyaki_configure_target(heyaki_m10_protocol_tests)
heyaki_add_runtime_test(
  heyaki_m10_protocol heyaki_m10_protocol_tests
  "unit;protocol;gateway;m10;security")

# M10 Round 2: gateway profile configuration (M10-04), the B-side admission
# engine (M10-05), the NodeConfig gateway_profiles wiring, and the M10-03
# scope/template exclusion regression against the TUI default pairing lists.
add_executable(heyaki_m10_gateway_policy_tests unit/m10_gateway_policy_test.cpp)
heyaki_enable_executor_exception_adapter_source(unit/m10_gateway_policy_test.cpp)
target_link_libraries(heyaki_m10_gateway_policy_tests PRIVATE
  heyaki::client
  executor::executor
  GTest::gtest_main
  OpenSSL::SSL)
heyaki_target_use_pinned_boost_asio(heyaki_m10_gateway_policy_tests)
heyaki_configure_target(heyaki_m10_gateway_policy_tests)
target_compile_definitions(heyaki_m10_gateway_policy_tests PRIVATE
  "HEYAKI_M10_GATEWAY_TEST_STATE_DIR=\"${HEYAKI_TEST_STATE_DIR}/m10-gateway\""
  "HEYAKI_M10_TUI_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}/../apps/tui\"")
heyaki_add_runtime_test(
  heyaki_m10_gateway_policy heyaki_m10_gateway_policy_tests
  "unit;m10;gateway;security")
set_tests_properties(heyaki_m10_gateway_policy PROPERTIES
  RESOURCE_LOCK heyaki_m3a_profile_state
  TIMEOUT 120)

# M10 Round 3: the B-side GatewayService (M10-07) and the A-side
# open_gateway_stream public API (M10-08) — initiator prelude semantics and
# dial deadline, admission/refusal accounting over the loopback session
# harness, real dials against a local echo target, injected-clock
# idle/duration/quota sweeps, session-close cleanup, and Node-level local
# validation plus the gateway.use scope gate over an authenticated LAN pair.
add_executable(heyaki_m10_gateway_service_tests unit/m10_gateway_service_test.cpp)
heyaki_enable_executor_exception_adapter_source(unit/m10_gateway_service_test.cpp)
target_link_libraries(heyaki_m10_gateway_service_tests PRIVATE
  heyaki::client
  executor::executor
  GTest::gtest_main
  OpenSSL::SSL)
heyaki_target_use_pinned_boost_asio(heyaki_m10_gateway_service_tests)
heyaki_configure_target(heyaki_m10_gateway_service_tests)
target_include_directories(heyaki_m10_gateway_service_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client"
  "${CMAKE_CURRENT_SOURCE_DIR}/unit")
target_compile_definitions(heyaki_m10_gateway_service_tests PRIVATE
  "HEYAKI_M10_SERVICE_TEST_STATE_DIR=\"${HEYAKI_TEST_STATE_DIR}/m10-gateway-service\"")
heyaki_add_runtime_test(
  heyaki_m10_gateway_service heyaki_m10_gateway_service_tests
  "unit;m10;gateway;concurrency")
set_tests_properties(heyaki_m10_gateway_service PROPERTIES
  RESOURCE_LOCK heyaki_m3a_profile_state
  TIMEOUT 180)

# M10 Round 4: initiator opening/on_connected semantics (M10-08), the
# serving-side human confirmation flow (M10-06), the SOCKS5 CONNECT frontend
# (M10-09) over a Node pair with a real borrowed Runtime, and TUI CLI parse
# smoke against the built heyaki-tui binary.
add_executable(heyaki_m10_round4_tests unit/m10_round4_test.cpp)
heyaki_enable_executor_exception_adapter_source(unit/m10_round4_test.cpp)
target_link_libraries(heyaki_m10_round4_tests PRIVATE
  heyaki::client
  heyaki::socks
  executor::executor
  GTest::gtest_main
  OpenSSL::SSL)
heyaki_target_use_pinned_boost_asio(heyaki_m10_round4_tests)
heyaki_configure_target(heyaki_m10_round4_tests)
target_include_directories(heyaki_m10_round4_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client"
  "${CMAKE_CURRENT_SOURCE_DIR}/unit")
target_compile_definitions(heyaki_m10_round4_tests PRIVATE
  "HEYAKI_M10_ROUND4_TEST_STATE_DIR=\"${HEYAKI_TEST_STATE_DIR}/m10-round4\"")
if(HEYAKI_BUILD_APPS)
  target_compile_definitions(heyaki_m10_round4_tests PRIVATE
    "HEYAKI_TUI_BINARY=\"$<TARGET_FILE:heyaki-tui>\"")
  add_dependencies(heyaki_m10_round4_tests heyaki-tui)
endif()
heyaki_add_runtime_test(
  heyaki_m10_round4 heyaki_m10_round4_tests
  "unit;m10;gateway;socks")
set_tests_properties(heyaki_m10_round4 PROPERTIES
  RESOURCE_LOCK heyaki_m3a_profile_state
  TIMEOUT 300)

# M10 Round 5: gateway metrics & path policy (M10-11: dial-sample ring/P95,
# export families, TURN-path refusal, confirm_denials) and the bounded audit
# trail (M10-12) at the service and Node level, plus the M10-10 scheduling
# evidence facts (STREAM_DATA frame class).
add_executable(heyaki_m10_metrics_audit_tests unit/m10_metrics_audit_test.cpp)
heyaki_enable_executor_exception_adapter_source(unit/m10_metrics_audit_test.cpp)
target_link_libraries(heyaki_m10_metrics_audit_tests PRIVATE
  heyaki::client
  executor::executor
  GTest::gtest_main
  OpenSSL::SSL)
heyaki_target_use_pinned_boost_asio(heyaki_m10_metrics_audit_tests)
heyaki_configure_target(heyaki_m10_metrics_audit_tests)
target_include_directories(heyaki_m10_metrics_audit_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client"
  "${CMAKE_CURRENT_SOURCE_DIR}/unit")
target_compile_definitions(heyaki_m10_metrics_audit_tests PRIVATE
  "HEYAKI_M10_METRICS_AUDIT_TEST_STATE_DIR=\"${HEYAKI_TEST_STATE_DIR}/m10-metrics-audit\"")
heyaki_add_runtime_test(
  heyaki_m10_metrics_audit heyaki_m10_metrics_audit_tests
  "unit;m10;gateway;metrics")
set_tests_properties(heyaki_m10_metrics_audit PROPERTIES
  RESOURCE_LOCK heyaki_m3a_profile_state
  TIMEOUT 300)

# M10 Round 6: protocol isolation across the session-restart epoch boundary
# for gateway streams — late old-epoch STREAM_* frames on the restarted
# session are dropped without state, the retired stream resets with its
# pending I/O (M5-18), on_connected never refires, and the epoch-2 successor
# serves a fresh gateway stream.
add_executable(heyaki_m10_isolation_tests unit/m10_isolation_test.cpp)
heyaki_enable_executor_exception_adapter_source(unit/m10_isolation_test.cpp)
target_link_libraries(heyaki_m10_isolation_tests PRIVATE
  heyaki::client
  executor::executor
  GTest::gtest_main
  OpenSSL::SSL)
heyaki_target_use_pinned_boost_asio(heyaki_m10_isolation_tests)
heyaki_configure_target(heyaki_m10_isolation_tests)
target_include_directories(heyaki_m10_isolation_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client"
  "${CMAKE_CURRENT_SOURCE_DIR}/unit")
target_compile_definitions(heyaki_m10_isolation_tests PRIVATE
  "HEYAKI_M10_ISOLATION_TEST_STATE_DIR=\"${HEYAKI_TEST_STATE_DIR}/m10-isolation\"")
heyaki_add_runtime_test(
  heyaki_m10_isolation heyaki_m10_isolation_tests
  "unit;m10;gateway;protocol")
set_tests_properties(heyaki_m10_isolation PROPERTIES
  RESOURCE_LOCK heyaki_m3a_profile_state
  TIMEOUT 300)

add_executable(heyaki_m8_service_tests
  unit/m8_codec_test.cpp
  unit/m8_shell_test.cpp
  unit/m8_vt_test.cpp
  unit/m8_pty_test.cpp)
target_link_libraries(heyaki_m8_service_tests PRIVATE
  heyaki::client
  heyaki::core
  heyaki::blake3
  executor::executor
  GTest::gtest_main)
target_include_directories(heyaki_m8_service_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client"
  "${CMAKE_CURRENT_SOURCE_DIR}/unit")
heyaki_target_use_pinned_boost_beast(heyaki_m8_service_tests)
heyaki_configure_target(heyaki_m8_service_tests)
heyaki_add_runtime_test(
  heyaki_m8_service heyaki_m8_service_tests
  "unit;session;security;protocol;concurrency;m8")

add_executable(heyaki_m7_service_tests
  unit/m7_codec_test.cpp
  unit/m7_event_test.cpp
  unit/m7_file_test.cpp)
target_link_libraries(heyaki_m7_service_tests PRIVATE
  heyaki::client
  heyaki::core
  heyaki::blake3
  executor::executor
  GTest::gtest_main)
target_include_directories(heyaki_m7_service_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client"
  "${CMAKE_CURRENT_SOURCE_DIR}/unit")
heyaki_configure_target(heyaki_m7_service_tests)
heyaki_add_runtime_test(
  heyaki_m7_service heyaki_m7_service_tests
  "unit;session;security;protocol;concurrency;m7")

add_executable(heyaki_m5_pairing_service_tests unit/m5_pairing_service_test.cpp)
target_link_libraries(heyaki_m5_pairing_service_tests PRIVATE
  heyaki::client
  heyaki::profile
  heyaki::sqlite
  GTest::gtest_main)
target_include_directories(heyaki_m5_pairing_service_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client"
  "${CMAKE_CURRENT_SOURCE_DIR}/unit")
heyaki_configure_target(heyaki_m5_pairing_service_tests)
heyaki_add_runtime_test(
  heyaki_m5_pairing heyaki_m5_pairing_service_tests
  "unit;security;profile;session")

add_executable(heyaki_m4_peer_session_tests unit/m4_peer_session_test.cpp)
target_link_libraries(heyaki_m4_peer_session_tests PRIVATE
  heyaki::client
  heyaki::core
  GTest::gtest_main)
target_include_directories(heyaki_m4_peer_session_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client")
heyaki_configure_target(heyaki_m4_peer_session_tests)
heyaki_add_runtime_test(
  heyaki_m4_peer_session heyaki_m4_peer_session_tests
  "unit;session;security;protocol")

add_executable(heyaki_m4_webrtc_transport_tests unit/m4_webrtc_transport_test.cpp)
target_link_libraries(heyaki_m4_webrtc_transport_tests PRIVATE
  heyaki::client
  heyaki::transport_webrtc
  executor::executor
  GTest::gtest_main)
target_include_directories(heyaki_m4_webrtc_transport_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/transport"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/transport/webrtc")
heyaki_configure_target(heyaki_m4_webrtc_transport_tests)
heyaki_enable_executor_exception_adapter_source(unit/m4_webrtc_transport_test.cpp)
heyaki_add_runtime_test(
  heyaki_m4_webrtc_transport heyaki_m4_webrtc_transport_tests
  "unit;transport;network;concurrency")
if(WIN32)
  set_tests_properties(heyaki_m4_webrtc_transport PROPERTIES
    ENVIRONMENT_MODIFICATION
      "PATH=path_list_prepend:$<TARGET_FILE_DIR:datachannel>")
endif()

add_executable(heyaki_m4_relay_route_tests unit/m4_relay_signaling_test.cpp)
target_link_libraries(heyaki_m4_relay_route_tests PRIVATE
  heyaki::relay
  heyaki_protocol_lite
  executor::executor
  heyaki::sqlite
  GTest::gtest_main
  OpenSSL::SSL
  OpenSSL::Crypto)
heyaki_target_use_pinned_boost_beast(heyaki_m4_relay_route_tests)
target_include_directories(heyaki_m4_relay_route_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src")
heyaki_configure_target(heyaki_m4_relay_route_tests)
target_compile_definitions(heyaki_m4_relay_route_tests PRIVATE
  "HEYAKI_M4_TEST_STATE_DIR=\"${HEYAKI_TEST_STATE_DIR}\"")
heyaki_add_runtime_test(
  heyaki_m4_relay_route heyaki_m4_relay_route_tests "unit;relay;signaling;security")

add_executable(heyaki_m4_path_policy_tests unit/m4_path_policy_test.cpp)
heyaki_enable_executor_exception_adapter_source(unit/m4_path_policy_test.cpp)
target_link_libraries(heyaki_m4_path_policy_tests PRIVATE
  heyaki::client
  executor::executor
  GTest::gtest_main
  OpenSSL::SSL)
heyaki_target_use_pinned_boost_asio(heyaki_m4_path_policy_tests)
heyaki_configure_target(heyaki_m4_path_policy_tests)
target_compile_definitions(heyaki_m4_path_policy_tests PRIVATE
  "HEYAKI_M4_PATH_TEST_STATE_DIR=\"${HEYAKI_TEST_STATE_DIR}\"")
heyaki_add_runtime_test(
  heyaki_m4_path_policy heyaki_m4_path_policy_tests "unit;transport;lan;security")
set_tests_properties(heyaki_m4_path_policy PROPERTIES
  RESOURCE_LOCK heyaki_m3a_profile_state)

add_executable(heyaki_m4_session_latency_tests unit/m4_session_latency_test.cpp)
heyaki_enable_executor_exception_adapter_source(unit/m4_session_latency_test.cpp)
target_link_libraries(heyaki_m4_session_latency_tests PRIVATE
  heyaki::client
  executor::executor
  GTest::gtest_main
  OpenSSL::SSL)
heyaki_target_use_pinned_boost_asio(heyaki_m4_session_latency_tests)
heyaki_configure_target(heyaki_m4_session_latency_tests)
target_compile_definitions(heyaki_m4_session_latency_tests PRIVATE
  "HEYAKI_M4_LATENCY_TEST_STATE_DIR=\"${HEYAKI_TEST_STATE_DIR}\"")
heyaki_add_runtime_test(
  heyaki_m4_session_latency heyaki_m4_session_latency_tests
  "performance;transport;lan")
set_tests_properties(heyaki_m4_session_latency PROPERTIES
  RESOURCE_LOCK heyaki_m3a_profile_state
  TIMEOUT 300)

add_executable(heyaki_m3b_relay_tests
  unit/m3b_relay_test.cpp
  unit/m3b_relay_database_test.cpp
  unit/m3b_relay_wss_client_test.cpp
  unit/m3b_relay_wss_control_test.cpp
  unit/m3b_relay_endpoint_test.cpp
  unit/m3b_relay_enrollment_client_test.cpp
  unit/m3b_relay_enrollment_test.cpp
  unit/m3b_relay_enrollment_service_test.cpp
  unit/m3b_relay_lease_test.cpp
  unit/m3b_relay_login_test.cpp
  unit/m3b_relay_rate_limiter_test.cpp
  unit/m3b_relay_ttl_test.cpp
  unit/m3b_relay_turn_credentials_test.cpp)
target_link_libraries(heyaki_m3b_relay_tests PRIVATE
  heyaki::relay
  heyaki_protocol_lite
  executor::executor
  heyaki::sqlite
  GTest::gtest_main
  OpenSSL::SSL
  OpenSSL::Crypto)
heyaki_target_use_pinned_boost_beast(heyaki_m3b_relay_tests)
target_include_directories(heyaki_m3b_relay_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client")
heyaki_configure_target(heyaki_m3b_relay_tests)
heyaki_enable_executor_exception_adapter_source(unit/m3b_relay_test.cpp)
target_compile_definitions(heyaki_m3b_relay_tests PRIVATE
  "HEYAKI_M3B_TEST_STATE_DIR=\"${HEYAKI_TEST_STATE_DIR}\"")
heyaki_add_runtime_test(
  heyaki_m3b_relay heyaki_m3b_relay_tests "unit;relay;network;security")
set_tests_properties(heyaki_m3b_relay PROPERTIES
  RESOURCE_LOCK heyaki_m3a_profile_state)

set(heyaki_public_header_sources)
foreach(public_header IN ITEMS
    error gateway identity ids lan_directory lan_protocol limits node operation password profile_store protocol relay_enrollment_client relay_wss_control runtime secret_backend
    security session_protocol signaling_protocol signaling_replay_cache signing time version wire)
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
if(WIN32)
  set_tests_properties(heyaki_module_linkage PROPERTIES
    ENVIRONMENT_MODIFICATION
      "PATH=path_list_prepend:$<TARGET_FILE_DIR:datachannel>")
endif()

add_library(heyaki_fuzz_harness OBJECT fuzz/protocol_fuzz.cpp)
target_link_libraries(heyaki_fuzz_harness PRIVATE heyaki::core heyaki_protocol_lite)
target_include_directories(heyaki_fuzz_harness PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/fuzz")
heyaki_configure_target(heyaki_fuzz_harness)

add_executable(heyaki_fuzz_smoke
  fuzz/fuzz_smoke.cpp
  fuzz/connection_state_fuzz.cpp
  fuzz/lan_state_fuzz.cpp
  fuzz/profile_store_fuzz.cpp
  $<TARGET_OBJECTS:heyaki_fuzz_harness>)
target_link_libraries(heyaki_fuzz_smoke PRIVATE
  heyaki::client
  heyaki::sqlite
  heyaki_protocol_lite)
target_include_directories(heyaki_fuzz_smoke PRIVATE
  "${HEYAKI_TEST_GENERATED_DIR}"
  "${PROJECT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/fuzz")
target_compile_definitions(heyaki_fuzz_smoke PRIVATE
  "HEYAKI_FUZZ_PROFILE_V1_FIXTURE=\"${CMAKE_CURRENT_SOURCE_DIR}/fixtures/profile_store_v1.sql\""
  "HEYAKI_FUZZ_REGRESSION_CORPUS_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus\"")
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

  add_executable(heyaki_lan_state_fuzzer
    fuzz/lan_state_fuzzer_entry.cpp
    fuzz/lan_state_fuzz.cpp)
  target_link_libraries(heyaki_lan_state_fuzzer PRIVATE heyaki::client)
  target_include_directories(heyaki_lan_state_fuzzer PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/fuzz")
  target_compile_options(heyaki_lan_state_fuzzer PRIVATE -fsanitize=fuzzer)
  target_link_options(heyaki_lan_state_fuzzer PRIVATE -fsanitize=fuzzer)
  heyaki_configure_target(heyaki_lan_state_fuzzer)

  add_executable(heyaki_connection_state_fuzzer
    fuzz/connection_state_fuzzer_entry.cpp
    fuzz/connection_state_fuzz.cpp)
  target_link_libraries(heyaki_connection_state_fuzzer PRIVATE heyaki::client)
  target_include_directories(heyaki_connection_state_fuzzer PRIVATE
    "${PROJECT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/fuzz")
  target_compile_options(heyaki_connection_state_fuzzer PRIVATE -fsanitize=fuzzer)
  target_link_options(heyaki_connection_state_fuzzer PRIVATE -fsanitize=fuzzer)
  heyaki_configure_target(heyaki_connection_state_fuzzer)

  add_executable(heyaki_profile_store_fuzzer
    fuzz/profile_store_fuzzer_entry.cpp
    fuzz/profile_store_fuzz.cpp)
  target_link_libraries(heyaki_profile_store_fuzzer PRIVATE
    heyaki::client
    heyaki::sqlite)
  target_include_directories(heyaki_profile_store_fuzzer PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/fuzz")
  target_compile_definitions(heyaki_profile_store_fuzzer PRIVATE
    "HEYAKI_FUZZ_PROFILE_V1_FIXTURE=\"${CMAKE_CURRENT_SOURCE_DIR}/fixtures/profile_store_v1.sql\"")
  target_compile_options(heyaki_profile_store_fuzzer PRIVATE -fsanitize=fuzzer)
  target_link_options(heyaki_profile_store_fuzzer PRIVATE -fsanitize=fuzzer)
  heyaki_configure_target(heyaki_profile_store_fuzzer)
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

add_executable(heyaki_m5_scheduler_benchmark performance/m5_scheduler_benchmark.cpp)
target_link_libraries(heyaki_m5_scheduler_benchmark PRIVATE heyaki::client)
target_include_directories(heyaki_m5_scheduler_benchmark PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../src/client")
heyaki_configure_target(heyaki_m5_scheduler_benchmark)
heyaki_add_runtime_test(
  heyaki_m5_scheduler heyaki_m5_scheduler_benchmark "performance;session;concurrency")
heyaki_add_runtime_test(
  heyaki_performance_smoke heyaki_performance_smoke "performance")

if(HEYAKI_BUILD_APPS)
  add_executable(heyaki_tui_setup_tests unit/tui_setup_test.cpp)
  target_link_libraries(heyaki_tui_setup_tests PRIVATE
    heyaki_tui_setup
    GTest::gtest_main)
  target_compile_definitions(heyaki_tui_setup_tests PRIVATE
    "HEYAKI_TUI_TEST_STATE_DIR=\"${HEYAKI_TEST_STATE_DIR}/tui-setup\"")
  heyaki_configure_target(heyaki_tui_setup_tests)
  heyaki_add_runtime_test(
    heyaki_tui_setup heyaki_tui_setup_tests "unit;tui;profile;security")

  heyaki_add_runtime_test(heyaki_relay_version heyaki-relay "relay" --version)
  heyaki_add_runtime_test(heyaki_tui_version heyaki-tui "tui" --version)
  add_test(NAME heyaki_tui_local_status
    COMMAND heyaki-tui --profile m3a-status --status)
  if(WIN32)
    set_tests_properties(heyaki_tui_local_status PROPERTIES
      ENVIRONMENT "LOCALAPPDATA=${HEYAKI_TEST_STATE_DIR}/tui-status"
      LABELS "tui;lan"
      PASS_REGULAR_EXPRESSION "LOCAL   not-initialized;LAN     stopped;RELAY   disabled;PAIRING unavailable")
  else()
    set_tests_properties(heyaki_tui_local_status PROPERTIES
      ENVIRONMENT "XDG_STATE_HOME=${HEYAKI_TEST_STATE_DIR}/tui-status"
      LABELS "tui;lan"
      PASS_REGULAR_EXPRESSION "LOCAL   not-initialized;LAN     stopped;RELAY   disabled;PAIRING unavailable")
  endif()
endif()

add_test(
  NAME heyaki_network_harness
  COMMAND "${HEYAKI_BASH_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/network/run_harness.sh"
    "$<TARGET_FILE:heyaki_m3a_lan_tests>")
set_tests_properties(heyaki_network_harness PROPERTIES
  LABELS "network;lan;security"
  RESOURCE_LOCK heyaki_m3a_profile_state
  SKIP_RETURN_CODE 77
  TIMEOUT 180)

if(HEYAKI_BUILD_APPS)
  add_test(
    NAME heyaki_m3b_relay_onboarding_harness
    COMMAND "${HEYAKI_BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/network/run_m3b_relay_onboarding_harness.sh"
      --relay-bin "$<TARGET_FILE:heyaki-relay>"
      --tui-bin "$<TARGET_FILE:heyaki-tui>"
      --demo-bin "$<TARGET_FILE:heyaki-m3b-relay-demo>"
      --work-dir "${HEYAKI_TEST_STATE_DIR}/m3b-onboarding")
  set_tests_properties(heyaki_m3b_relay_onboarding_harness PROPERTIES
    LABELS "network;relay;tui;security"
    SKIP_RETURN_CODE 77
    # The inner TUI driver carries its own timeout, so the outer budget only
    # needs to absorb slow runners: the supply-chain job runs the full suite
    # from -g binaries (an order bigger) and drew the full 120s twice on
    # 2026-09-18. Match the m4 session harness headroom.
    TIMEOUT 240)

  add_test(
    NAME heyaki_m4_tui_session_harness
    COMMAND "${HEYAKI_BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/network/run_m4_tui_session_harness.sh"
      --tui-bin "$<TARGET_FILE:heyaki-tui>"
      --work-dir "${HEYAKI_TEST_STATE_DIR}/m4-tui-session")
  set_tests_properties(heyaki_m4_tui_session_harness PROPERTIES
    LABELS "network;tui;lan;security"
    RESOURCE_LOCK heyaki_m3a_profile_state
    SKIP_RETURN_CODE 77
    TIMEOUT 180)

  add_test(
    NAME heyaki_m6_tui_service_harness
    COMMAND "${HEYAKI_BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/network/run_m6_tui_service_harness.sh"
      --tui-bin "$<TARGET_FILE:heyaki-tui>"
      --work-dir "${HEYAKI_TEST_STATE_DIR}/m6-tui-service")
  set_tests_properties(heyaki_m6_tui_service_harness PROPERTIES
    LABELS "network;tui;lan;security;m6"
    RESOURCE_LOCK heyaki_m3a_profile_state
    SKIP_RETURN_CODE 77
    TIMEOUT 330)

  add_test(
    NAME heyaki_m6_semantics_smoke
    COMMAND "$<TARGET_FILE:heyaki-m6-message-rpc-demo>" semantics)
  set_tests_properties(heyaki_m6_semantics_smoke PROPERTIES
    LABELS "m6;docs"
    PASS_REGULAR_EXPRESSION "outcome_unknown;admission;unimplemented \\(12\\)")
endif()

if(TARGET heyaki-m7-data-demo)
  add_test(
    NAME heyaki_m7_semantics_smoke
    COMMAND "$<TARGET_FILE:heyaki-m7-data-demo>" semantics)
  set_tests_properties(heyaki_m7_semantics_smoke PROPERTIES
    LABELS "m7;docs"
    PASS_REGULAR_EXPRESSION "invalid_topic;unsafe_name;peer_offline;M7_SEMANTICS_OK")
endif()

if(WIN32)
  find_program(HEYAKI_POWERSHELL_EXECUTABLE NAMES pwsh powershell REQUIRED)
  add_test(
    NAME heyaki_windows_firewall_harness
    COMMAND "${HEYAKI_POWERSHELL_EXECUTABLE}"
      -NoProfile
      -ExecutionPolicy Bypass
      -File "${CMAKE_CURRENT_SOURCE_DIR}/network/run_windows_firewall_harness.ps1"
      -TestBinary "$<TARGET_FILE:heyaki_m3a_lan_tests>")
  set_tests_properties(heyaki_windows_firewall_harness PROPERTIES
    LABELS "network;lan;security;windows"
    SKIP_RETURN_CODE 77
    TIMEOUT 180)
  if(HEYAKI_BUILD_APPS)
    # M9-07: Windows-side e2e connectivity matrix (LAN-only, relay-signaled
    # direct, TURN/UDP via the libjuice test TURN server, firewall UDP
    # block) with the initiator role swapped between the peers.
    add_test(
      NAME heyaki_windows_network_matrix
      COMMAND "${HEYAKI_POWERSHELL_EXECUTABLE}"
        -NoProfile
        -ExecutionPolicy Bypass
        -File "${CMAKE_CURRENT_SOURCE_DIR}/network/run_windows_network_matrix.ps1"
        -MatrixBin "$<TARGET_FILE:heyaki-m4-matrix-node>"
        -RelayBin "$<TARGET_FILE:heyaki-relay>"
        -DemoBin "$<TARGET_FILE:heyaki-m3b-relay-demo>"
        -TurnServerBin "$<TARGET_FILE:heyaki-test-turn-server>")
    set_tests_properties(heyaki_windows_network_matrix PROPERTIES
      LABELS "network;relay;windows;m9"
      SKIP_RETURN_CODE 77
      TIMEOUT 900)
  endif()
endif()

add_test(
  NAME heyaki_coturn_deployment_contract
  COMMAND "${CMAKE_COMMAND}"
    "-DHEYAKI_COTURN_DIR=${CMAKE_CURRENT_SOURCE_DIR}/../deploy/coturn"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/deployment/CheckCoturnDeployment.cmake")
set_tests_properties(heyaki_coturn_deployment_contract PROPERTIES
  LABELS "relay;network;security")

if(HEYAKI_BUILD_APPS)
  add_test(
    NAME heyaki_coturn_topology_check
    COMMAND "${HEYAKI_BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/../deploy/coturn/run_topology.sh"
      --relay-bin "$<TARGET_FILE:heyaki-relay>"
      --check-only)
  set_tests_properties(heyaki_coturn_topology_check PROPERTIES
    LABELS "relay;network"
    SKIP_RETURN_CODE 77
    TIMEOUT 60)

  add_test(
    NAME heyaki_m4_network_matrix
    COMMAND "${HEYAKI_BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/../deploy/coturn/run_network_matrix.sh"
      --relay-bin "$<TARGET_FILE:heyaki-relay>"
      --matrix-bin "$<TARGET_FILE:heyaki-m4-matrix-node>"
      --demo-bin "$<TARGET_FILE:heyaki-m3b-relay-demo>")
  set_tests_properties(heyaki_m4_network_matrix PROPERTIES
    LABELS "relay;network;transport"
    SKIP_RETURN_CODE 77
    TIMEOUT 900)

  add_test(
    NAME heyaki_m9_nat_matrix
    COMMAND "${HEYAKI_BASH_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/../deploy/coturn/run_nat_matrix.sh"
    --relay-bin "$<TARGET_FILE:heyaki-relay>"
    --matrix-bin "$<TARGET_FILE:heyaki-m4-matrix-node>"
    --demo-bin "$<TARGET_FILE:heyaki-m3b-relay-demo>")
  set_tests_properties(heyaki_m9_nat_matrix PROPERTIES
    LABELS "relay;network;nat;m9"
    SKIP_RETURN_CODE 77
    TIMEOUT 1500)

  add_test(
    NAME heyaki_m9_fault_matrix
    COMMAND "${HEYAKI_BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/../deploy/coturn/run_fault_matrix.sh"
      --relay-bin "$<TARGET_FILE:heyaki-relay>"
      --matrix-bin "$<TARGET_FILE:heyaki-m4-matrix-node>"
      --demo-bin "$<TARGET_FILE:heyaki-m3b-relay-demo>")
  set_tests_properties(heyaki_m9_fault_matrix PROPERTIES
    LABELS "relay;network;fault;m9"
    SKIP_RETURN_CODE 77
    TIMEOUT 1500)

  # M10 Round 6 gateway matrix: netns topology where the gateway client can
  # reach the target ONLY through the serving node's gateway proxy (direct
  # path DROPed). Echo tunnel, forced-TURN tunnel, SOCKS5 curl (IP + split
  # DNS), and the direct_only path-policy refusal. Root-gated; skips with 77.
  add_test(
    NAME heyaki_m10_gateway_matrix
    COMMAND "${HEYAKI_BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/../deploy/coturn/run_gateway_matrix.sh"
      --relay-bin "$<TARGET_FILE:heyaki-relay>"
      --matrix-bin "$<TARGET_FILE:heyaki-m4-matrix-node>"
      --demo-bin "$<TARGET_FILE:heyaki-m3b-relay-demo>")
  set_tests_properties(heyaki_m10_gateway_matrix PROPERTIES
    LABELS "network;m10;gateway"
    SKIP_RETURN_CODE 77
    TIMEOUT 1500)

  # M9-09 soak harness: session churn with per-cycle RSS/fd/session/replay
  # samples on a long-lived initiator, distinct-device discovery churn against
  # a long-lived relay, and capacity overload on a tight second relay. Runs on
  # loopback (no root, no coturn); gated by HEYAKI_REQUIRE_M9_SOAK so default
  # suites and sanitizer presets stay fast. Longer (24/72h) runs scale the
  # HEYAKI_SOAK_* knobs documented in docs/operations/runbook.md.
  add_test(
    NAME heyaki_m9_soak
    COMMAND "${HEYAKI_BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/network/run_m9_soak_harness.sh"
      --relay-bin "$<TARGET_FILE:heyaki-relay>"
      --matrix-bin "$<TARGET_FILE:heyaki-m4-matrix-node>"
      --demo-bin "$<TARGET_FILE:heyaki-m3b-relay-demo>"
      --work-dir "${HEYAKI_TEST_STATE_DIR}/m9-soak")
  set_tests_properties(heyaki_m9_soak PROPERTIES
    LABELS "network;relay;soak;m9"
    SKIP_RETURN_CODE 77
    TIMEOUT 1500)

  # M9-10 benchmark harness: registration/direct-connect/TURN P95 loops plus
  # the long-lived latency suite (message RTT, sequential/concurrent RPC,
  # event fan-out, single/concurrent file throughput, shell ping latency idle
  # and under a bulk push) with relay footprint scrapes. Loopback like the
  # soak harness; gated by HEYAKI_REQUIRE_M9_BENCH. The measured numbers feed
  # the M9-11 parameter freeze and the v1 acceptance record.
  add_test(
    NAME heyaki_m9_bench
    COMMAND "${HEYAKI_BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/network/run_m9_bench_harness.sh"
      --relay-bin "$<TARGET_FILE:heyaki-relay>"
      --matrix-bin "$<TARGET_FILE:heyaki-m4-matrix-node>"
      --demo-bin "$<TARGET_FILE:heyaki-m3b-relay-demo>"
      --turn-bin "$<TARGET_FILE:heyaki-test-turn-server>"
      --work-dir "${HEYAKI_TEST_STATE_DIR}/m9-bench")
  set_tests_properties(heyaki_m9_bench PROPERTIES
    LABELS "network;relay;bench;m9"
    SKIP_RETURN_CODE 77
    TIMEOUT 1500)
endif()

add_test(
  NAME heyaki_coturn_allocation_probe
  COMMAND "${HEYAKI_BASH_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/../deploy/coturn/run_allocation_probe.sh")
set_tests_properties(heyaki_coturn_allocation_probe PROPERTIES
  LABELS "relay;network;security"
  SKIP_RETURN_CODE 77
  TIMEOUT 90)

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
    "-DHEYAKI_PROJECT_VERSION=${PROJECT_VERSION}"
    "-DHEYAKI_BUILD_COMMIT=${HEYAKI_RESOLVED_BUILD_COMMIT}"
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

# M9-14 hardening verification: shipped Linux executables must carry the ELF
# mitigations HEYAKI_HARDENING produces (PIE, NX stack, full RELRO, stack
# canary; FORTIFY additionally in optimized single-config builds). Sanitizer
# presets and non-Linux hosts are excluded at registration time; Windows
# mitigations (/GS /guard:cf /GUARD:CF /CETCOMPAT) are compile-time flags
# without an equivalent script and are recorded in the release audit instead.
if(HEYAKI_BUILD_APPS AND HEYAKI_HARDENING AND UNIX AND NOT APPLE AND
   HEYAKI_SANITIZER STREQUAL "none")
  set(heyaki_hardening_check_args)
  if(CMAKE_BUILD_TYPE MATCHES "^(Release|RelWithDebInfo|MinSizeRel)$")
    set(heyaki_hardening_check_args --expect-fortify)
  endif()
  add_test(
    NAME heyaki_m9_hardening_check
    COMMAND "${HEYAKI_BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/supply_chain/run_hardening_check.sh"
      ${heyaki_hardening_check_args}
      "$<TARGET_FILE:heyaki-relay>"
      "$<TARGET_FILE:heyaki-tui>"
      "$<TARGET_FILE:heyaki-m4-matrix-node>"
      "$<TARGET_FILE:heyaki-test-turn-server>")
  set_tests_properties(heyaki_m9_hardening_check PROPERTIES
    LABELS "security;build;m9"
    TIMEOUT 120)
endif()

# M9-14 release signing roundtrip: a miniature bundle from real build
# artifacts (binary + SPDX SBOM + license manifest) goes through
# keygen/manifest/sign/verify/check, and every tamper direction (artifact,
# manifest, wrong key, extra/missing file) must be rejected. The bundle's
# binary is the signing tool itself: sanitizer Debug binaries of the relay
# reach hundreds of MB, and re-hashing such an artifact repeatedly is pure
# I/O time that once blew the CI timeout without testing anything new.
if(HEYAKI_BUILD_APPS)
  add_test(
    NAME heyaki_m9_release_signing
    COMMAND "${HEYAKI_BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/supply_chain/run_release_signing_test.sh"
      --sign-bin "$<TARGET_FILE:heyaki-release-sign>"
      --artifact-bin "$<TARGET_FILE:heyaki-release-sign>"
      --sbom "${HEYAKI_SBOM_FILE}"
      --licenses "${HEYAKI_LICENSE_MANIFEST_FILE}"
      --work-dir "${HEYAKI_TEST_STATE_DIR}/release-signing")
  set_tests_properties(heyaki_m9_release_signing PROPERTIES
    LABELS "security;release;m9"
    TIMEOUT 300)
endif()

# M9-14 dependency vulnerability scan (OSV.dev): real pin closure must be
# clean (or triaged), a planted vulnerable commit must be reported, and the
# triage file must be honored. Needs the OSV API; self-gates with SKIP 77
# unless HEYAKI_REQUIRE_VULN_SCAN=1 (CI supply-chain job).
find_program(HEYAKI_PYTHON3_EXECUTABLE NAMES python3)
if(HEYAKI_PYTHON3_EXECUTABLE)
  add_test(
    NAME heyaki_m9_vulnerability_scan
    COMMAND "${HEYAKI_BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/supply_chain/run_vulnerability_scan_test.sh")
  set_tests_properties(heyaki_m9_vulnerability_scan PROPERTIES
    LABELS "security;supply-chain;m9"
    SKIP_RETURN_CODE 77
    TIMEOUT 300)
endif()

# M9-14 secret scan (pinned gitleaks, full git history): downloads the
# digest-pinned build when HEYAKI_GITLEAKS_BIN is not provided, proves the
# rule set fires on a planted credential, then scans the repository history
# with the reviewed allowlist. Self-gates with SKIP 77 unless
# HEYAKI_REQUIRE_SECRET_SCAN=1 (CI supply-chain job).
add_test(
  NAME heyaki_m9_secret_scan
  COMMAND "${HEYAKI_BASH_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/run_secret_scan.sh"
    --repo "${CMAKE_CURRENT_SOURCE_DIR}/.."
    --cache-dir "${HEYAKI_TEST_STATE_DIR}/secret-scan")
set_tests_properties(heyaki_m9_secret_scan PROPERTIES
  LABELS "security;supply-chain;m9"
  SKIP_RETURN_CODE 77
  TIMEOUT 600)

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
    "-DHEYAKI_CONSUMER_OPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}"
    "-DHEYAKI_CONFIG=$<CONFIG>"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/consumer/RunConsumerTest.cmake")
set_tests_properties(heyaki_installed_consumer PROPERTIES LABELS "integration")

# M9-17: release packaging verification (Linux, non-sanitizer). Installs into
# a scratch prefix, asserts the packaging inventory, splits debug symbols,
# runs the stripped binaries, creates + extracts the tarballs, and simulates a
# manifest-driven uninstall. Exit 77 (skip) when the build carries no debug
# info; the CI supply-chain job configures with -g so the full flow runs.
if(UNIX AND NOT APPLE AND NOT WIN32 AND HEYAKI_SANITIZER STREQUAL "none"
   AND NOT CMAKE_CROSSCOMPILING)
  find_program(HEYAKI_OBJCOPY objcopy)
  find_program(HEYAKI_READELF readelf)
  find_program(HEYAKI_TAR tar)
  find_program(HEYAKI_BASH_INTERPRETER bash)
  if(HEYAKI_OBJCOPY AND HEYAKI_READELF AND HEYAKI_TAR
     AND HEYAKI_BASH_INTERPRETER)
    add_test(
      NAME heyaki_m9_package
      COMMAND "${HEYAKI_BASH_INTERPRETER}"
        "${PROJECT_SOURCE_DIR}/scripts/package_release.sh"
        "--build-dir" "${CMAKE_BINARY_DIR}"
        "--output" "${CMAKE_CURRENT_BINARY_DIR}/package-test")
    set_tests_properties(heyaki_m9_package PROPERTIES
      LABELS "integration;release;m9;packaging"
      TIMEOUT 900
      SKIP_RETURN_CODE 77)
  endif()
endif()

if(WIN32)
  set_tests_properties(heyaki_public_headers
    PROPERTIES LABELS "protocol;security;windows")
  set_tests_properties(heyaki_installed_consumer
    PROPERTIES LABELS "integration;windows")
endif()
