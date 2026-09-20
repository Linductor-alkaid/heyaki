cmake_minimum_required(VERSION 3.25)

project(
  heyaki
  VERSION 1.0.1
  DESCRIPTION "Device-to-device communication infrastructure"
  LANGUAGES C CXX)

# Abseil's drop-in types change ABI with the active C++ language standard.
# Keep every in-tree dependency on the same standard as Heyaki targets.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CTest)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(HEYAKI_BUILD_APPS "Build heyaki-relay and heyaki-tui" ON)
option(HEYAKI_FETCH_DEPENDENCIES
  "Fetch and synchronize missing pinned dependencies during CMake configure" ON)
option(HEYAKI_VERIFY_DEPENDENCIES "Verify pinned dependency checkouts at configure time" ON)
option(HEYAKI_VERIFY_ZSTD_DEPENDENCY
  "Include the optional zstd checkout in configure-time pin verification" OFF)
option(HEYAKI_WARNINGS_AS_ERRORS "Treat Heyaki warnings as errors" OFF)
option(HEYAKI_ENABLE_EXCEPTIONS "Build Heyaki targets with C++ exception support" ON)
option(HEYAKI_ENABLE_CLANG_TIDY "Run clang-tidy while compiling Heyaki targets" OFF)
option(HEYAKI_ENABLE_IWYU "Run include-what-you-use while compiling Heyaki targets" OFF)
option(HEYAKI_REQUIRE_SANITIZER_RUNTIME
  "Fail instead of skipping when the host cannot run a selected sanitizer" OFF)
option(HEYAKI_BUILD_FUZZERS "Build libFuzzer protocol targets (Clang only)" OFF)
option(HEYAKI_HARDENING
  "Compile and link release artifacts with exploit mitigations (PIE, full RELRO, NX stack, stack protector, FORTIFY, CET/CF)"
  ON)
# M9-19: ICE backend for the pinned libdatachannel. `juice` builds the vendored
# libjuice (TURN client over UDP only). `nice` builds against the system
# libnice/GLib pair (same class of platform dependency as OpenSSL) and enables
# the TURN-over-TCP client (RFC 5766 over a TCP control connection, ICE-TCP per
# RFC 6544). TURN/TLS is NOT provided by either backend: libnice's TURN_TLS
# relay type silently degrades to plaintext TURN/TCP for standard ICE, so
# TURN/TLS policies are rejected at every layer regardless of backend. Linux
# only; the Windows/Android backend choice is a separate decision point
# (M9-19 record).
set(HEYAKI_ICE_BACKEND "juice" CACHE STRING
  "ICE backend for the pinned libdatachannel: juice (vendored, TURN/UDP only) or nice (system libnice, TURN/UDP+TCP)")

set(HEYAKI_SANITIZER "none" CACHE STRING "Sanitizer: none, address, undefined, or thread")
set_property(CACHE HEYAKI_SANITIZER PROPERTY STRINGS none address undefined thread)
set(HEYAKI_BUILD_COMMIT "" CACHE STRING "Override the source commit reported by build_info()")

set(HEYAKI_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated" CACHE PATH
    "Generated protocol and build metadata directory")
set(HEYAKI_TEST_STATE_DIR "${CMAKE_CURRENT_BINARY_DIR}/test-state" CACHE PATH
    "Temporary profiles, credentials, and databases used by tests")
set(HEYAKI_FUZZ_CORPUS_DIR "${CMAKE_CURRENT_BINARY_DIR}/fuzz-corpus" CACHE PATH
    "Generated fuzz corpus directory")
set(HEYAKI_INSTALL_PREFIX "${CMAKE_CURRENT_BINARY_DIR}/install" CACHE PATH
    "Local installation directory used by the automatic heyaki-deploy target")
option(HEYAKI_AUTO_INSTALL
  "Install Heyaki artifacts into HEYAKI_INSTALL_PREFIX after each successful build" ON)

function(heyaki_require_binary_path variable_name)
  cmake_path(ABSOLUTE_PATH ${variable_name} NORMALIZE OUTPUT_VARIABLE absolute_path)
  cmake_path(IS_PREFIX CMAKE_BINARY_DIR "${absolute_path}" NORMALIZE is_in_build_tree)
  if(NOT is_in_build_tree)
    message(FATAL_ERROR
      "${variable_name} must be inside the build tree to keep generated data and credentials "
      "out of the source tree. Got: ${absolute_path}")
  endif()
  set(${variable_name} "${absolute_path}" PARENT_SCOPE)
endfunction()

heyaki_require_binary_path(HEYAKI_GENERATED_DIR)
heyaki_require_binary_path(HEYAKI_TEST_STATE_DIR)
heyaki_require_binary_path(HEYAKI_FUZZ_CORPUS_DIR)
set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_CLEAN_FILES
  "${HEYAKI_GENERATED_DIR};${HEYAKI_TEST_STATE_DIR};${HEYAKI_FUZZ_CORPUS_DIR}")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(HeyakiDependencies)
include(HeyakiProjectOptions)
include(HeyakiVendoredRuntime)
include(HeyakiVersion)

if(HEYAKI_FETCH_DEPENDENCIES OR HEYAKI_VERIFY_DEPENDENCIES OR BUILD_TESTING)
  heyaki_verify_dependencies()
endif()

# M9-14 hardening: link-level mitigations only hold when every object that
# goes into the release binaries is built position independent, and the
# object-level mitigations are worth the most in the vendored C libraries that
# parse untrusted input. Keep this project-wide (it also covers executor,
# libdatachannel, and the test-only protobuf/abseil/googletree builds) instead
# of Heyaki-target-only; executable/link flags are attached per Heyaki target
# in heyaki_configure_target(). FORTIFY applies to optimized configurations
# only: at -O0 glibc warns that it is inactive, which is fatal under
# HEYAKI_WARNINGS_AS_ERRORS.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(HEYAKI_HARDENING AND NOT MSVC AND
   CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
  add_compile_options(-fstack-protector-strong)
  if(HEYAKI_HARDENING_CET_FLAGS)
    add_compile_options(${HEYAKI_HARDENING_CET_FLAGS})
  endif()
  if(HEYAKI_HARDENING_FORTIFY_SOURCE)
    add_compile_options(
      "$<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-D_FORTIFY_SOURCE=${HEYAKI_HARDENING_FORTIFY_SOURCE}>")
  endif()
endif()

heyaki_resolve_build_commit(HEYAKI_RESOLVED_BUILD_COMMIT)
heyaki_add_pinned_boost_asio()
heyaki_add_pinned_boost_beast()
heyaki_add_vendored_sodium()
heyaki_add_vendored_blake3()
heyaki_add_vendored_sqlite()
find_package(OpenSSL 3.0 REQUIRED COMPONENTS SSL Crypto)
if(OPENSSL_VERSION VERSION_GREATER_EQUAL 4.0)
  message(FATAL_ERROR
    "Heyaki M3A freezes the OpenSSL 3.x ABI line; got ${OPENSSL_VERSION}")
endif()

set(EXECUTOR_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(EXECUTOR_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(EXECUTOR_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(EXECUTOR_ENABLE_GPU OFF CACHE BOOL "" FORCE)
set(EXECUTOR_ENABLE_CUDA OFF CACHE BOOL "" FORCE)
set(EXECUTOR_ENABLE_OPENCL OFF CACHE BOOL "" FORCE)
set(EXECUTOR_ENABLE_TSAN OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/executor)

# Heyaki owns the libdatachannel lifecycle through WebRtcTransportSession. Keep the
# pinned dependency on its minimal DataChannel profile; media and the standalone
# websocket API are not part of the v1 data plane. The pinned release's MSVC install
# rule requests a linker PDB for its primary target, so that target must be shared on
# Windows. Its dependency libraries and every Heyaki target remain static.
set(NO_MEDIA ON CACHE BOOL "" FORCE)
set(NO_WEBSOCKET ON CACHE BOOL "" FORCE)
if(WIN32)
  set(BUILD_SHARED_LIBS ON CACHE BOOL "" FORCE)
else()
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
endif()
set(BUILD_SHARED_DEPS_LIBS OFF CACHE BOOL "" FORCE)
set(NO_EXAMPLES ON CACHE BOOL "" FORCE)
set(NO_TESTS ON CACHE BOOL "" FORCE)
set(HEYAKI_WEBRTC_TCP_TURN 0)
if(HEYAKI_ICE_BACKEND STREQUAL "nice")
  if(WIN32)
    message(FATAL_ERROR
      "HEYAKI_ICE_BACKEND=nice is not available on Windows: the libnice backend "
      "pulls GLib, and the Windows ICE backend choice is a separate decision "
      "(M9-19). Use the default juice backend.")
  endif()
  # Resolve libnice through the pinned dependency's own find modules so the
  # probe stays identical to what libdatachannel consumes. The version floor
  # freezes the ubuntu-24.04 distro line (libnice 0.1.21, GLib 2.80): libnice
  # is a system dependency like OpenSSL, not a lock-file atom, so the floor is
  # the pin (see docs/supply-chain/dependency-policy.md).
  list(APPEND CMAKE_MODULE_PATH
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libdatachannel/cmake/Modules")
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(HEYAKI_PC_LIBNICE REQUIRED nice)
  if(HEYAKI_PC_LIBNICE_VERSION VERSION_LESS 0.1.21)
    message(FATAL_ERROR
      "HEYAKI_ICE_BACKEND=nice requires libnice >= 0.1.21 (ubuntu-24.04 distro "
      "line), found ${HEYAKI_PC_LIBNICE_VERSION}")
  endif()
  find_package(LibNice REQUIRED)
  set(USE_NICE ON CACHE BOOL "" FORCE)
  set(HEYAKI_WEBRTC_TCP_TURN 1)
  message(STATUS
    "Heyaki ICE backend: libnice ${HEYAKI_PC_LIBNICE_VERSION} (TURN/UDP+TCP)")
elseif(NOT HEYAKI_ICE_BACKEND STREQUAL "juice")
  message(FATAL_ERROR
    "HEYAKI_ICE_BACKEND must be 'juice' or 'nice', got '${HEYAKI_ICE_BACKEND}'")
else()
  set(USE_NICE OFF CACHE BOOL "" FORCE)
  message(STATUS "Heyaki ICE backend: vendored libjuice (TURN/UDP only)")
endif()
add_subdirectory(third_party/libdatachannel)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

if(NOT HEYAKI_SANITIZER STREQUAL "none" AND
   CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
  if(HEYAKI_SANITIZER STREQUAL "address")
    set(heyaki_executor_sanitizer_flag -fsanitize=address)
  elseif(HEYAKI_SANITIZER STREQUAL "undefined")
    set(heyaki_executor_sanitizer_flag -fsanitize=undefined)
  elseif(HEYAKI_SANITIZER STREQUAL "thread")
    set(heyaki_executor_sanitizer_flag -fsanitize=thread)
  endif()
  target_compile_options(executor PRIVATE
    "${heyaki_executor_sanitizer_flag}" -fno-omit-frame-pointer)
  target_link_options(executor PUBLIC
    "${heyaki_executor_sanitizer_flag}" -fno-omit-frame-pointer)
endif()

set(HEYAKI_PROTOCOL_VERSION_MAJOR 1)
set(HEYAKI_PROTOCOL_VERSION_MINOR 3)
set(HEYAKI_BUILD_FEATURE_RELAY ${HEYAKI_BUILD_APPS})
set(HEYAKI_BUILD_FEATURE_TUI ${HEYAKI_BUILD_APPS})
set(HEYAKI_BUILD_FEATURE_ZSTD OFF)
file(MAKE_DIRECTORY "${HEYAKI_GENERATED_DIR}/heyaki/detail")
configure_file(
  cmake/build_config.hpp.in
  "${HEYAKI_GENERATED_DIR}/heyaki/detail/build_config.hpp"
  @ONLY)

add_library(heyaki_core
  src/core/error.cpp
  src/core/event_protocol.cpp
  src/core/file_protocol.cpp
  src/core/frame_stream.cpp
  src/core/gateway_protocol.cpp
  src/core/identity.cpp
  src/core/ids.cpp
  src/core/lan_protocol.cpp
  src/core/limits.cpp
  src/core/message_protocol.cpp
  src/core/metrics.cpp
  src/core/operation.cpp
  src/core/pairing_protocol.cpp
  src/core/protocol.cpp
  src/core/rpc_protocol.cpp
  src/core/security.cpp
  src/core/session_protocol.cpp
  src/core/session_restart.cpp
  src/core/shell_protocol.cpp
  src/core/shell_terminal.cpp
  src/core/signaling_protocol.cpp
  src/core/signaling_replay_cache.cpp
  src/core/signing.cpp
  src/core/trust_grant.cpp
  src/core/version.cpp
  src/core/wire.cpp)
add_library(heyaki::core ALIAS heyaki_core)
set_target_properties(heyaki_core PROPERTIES EXPORT_NAME core OUTPUT_NAME heyaki_core)
target_compile_features(heyaki_core PUBLIC cxx_std_20)
target_compile_features(heyaki_core PRIVATE c_std_11)
target_include_directories(heyaki_core
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<BUILD_INTERFACE:${HEYAKI_GENERATED_DIR}>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
  PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src"
          "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/src/libsodium/include")
target_link_libraries(heyaki_core PRIVATE heyaki::sodium heyaki::blake3)
heyaki_configure_target(heyaki_core)

add_library(heyaki_profile
  src/profile/password.cpp
  src/profile/profile_store.cpp
  src/profile/secret_backend.cpp)
add_library(heyaki::profile ALIAS heyaki_profile)
set_target_properties(heyaki_profile PROPERTIES EXPORT_NAME profile OUTPUT_NAME heyaki_profile)
target_compile_features(heyaki_profile PUBLIC cxx_std_20)
target_link_libraries(heyaki_profile
  PUBLIC heyaki::core
  PRIVATE heyaki::sodium heyaki::sqlite)
if(WIN32)
  target_link_libraries(heyaki_profile PRIVATE crypt32)
elseif(CMAKE_DL_LIBS)
  target_link_libraries(heyaki_profile PRIVATE ${CMAKE_DL_LIBS})
endif()
heyaki_configure_target(heyaki_profile)

add_library(heyaki_client
  src/client/byte_stream.cpp
  src/client/gateway_service.cpp
  src/client/byte_stream_facade.cpp
  src/client/connection_attempt.cpp
  src/client/event_service.cpp
  src/client/file_service.cpp
  src/client/file_store.cpp
  src/client/message_service.cpp
  src/client/peer_session.cpp
  src/client/rpc_service.cpp
  src/client/lan_directory.cpp
  src/client/module.cpp
  src/client/node.cpp
  src/client/pairing_service.cpp
  src/client/relay_enrollment_client.cpp
  src/client/relay_wss_client.cpp
  src/client/relay_wss_control.cpp
  src/client/runtime.cpp
  src/client/session_channels.cpp
  src/client/shell_pty.cpp
  src/client/shell_service.cpp
  src/client/signaling_coordinator.cpp
  src/relay/relay_endpoint.cpp
  src/relay/relay_enrollment.cpp
  src/relay/relay_login.cpp)
add_library(heyaki::client ALIAS heyaki_client)
set_target_properties(heyaki_client PROPERTIES EXPORT_NAME client OUTPUT_NAME heyaki_client)
target_compile_features(heyaki_client PUBLIC cxx_std_20)
target_include_directories(heyaki_client PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src/transport")
target_link_libraries(heyaki_client
  PUBLIC heyaki::profile
  PRIVATE executor::executor heyaki::sodium heyaki::blake3 OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
  target_link_libraries(heyaki_client PRIVATE iphlpapi ws2_32)
endif()
heyaki_target_use_pinned_boost_beast(heyaki_client)
# forkpty() lives in libutil on glibc < 2.34 (the Ubuntu 20.04 baseline);
# newer glibc merged it into libc and keeps an -lutil stub, so probing and
# linking is correct on both.
include(CheckLibraryExists)
check_library_exists(util forkpty "" HEYAKI_HAVE_LIBUTIL_FORKPTY)
if(HEYAKI_HAVE_LIBUTIL_FORKPTY)
  target_link_libraries(heyaki_client PRIVATE util)
endif()
heyaki_configure_target(heyaki_client)
heyaki_enable_executor_exception_adapter_source(src/client/node.cpp)
heyaki_enable_executor_exception_adapter_source(src/client/relay_wss_client.cpp)
heyaki_enable_executor_exception_adapter_source(src/client/runtime.cpp)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  # GCC 13 Release optimization reports executor::comm::BoundedQueue's
  # std::optional<Item> storage as uninitialized when Item contains this
  # translation unit's variant with a vector. Retain the diagnostic without
  # treating this pinned dependency false positive as a Heyaki build failure.
  set_property(SOURCE src/client/node.cpp APPEND PROPERTY COMPILE_OPTIONS
    "$<$<CONFIG:Release>:-Wno-error=uninitialized>")
endif()

add_library(heyaki_services src/services/module.cpp)
add_library(heyaki::services ALIAS heyaki_services)
set_target_properties(heyaki_services PROPERTIES EXPORT_NAME services OUTPUT_NAME heyaki_services)
target_compile_features(heyaki_services PUBLIC cxx_std_20)
target_link_libraries(heyaki_services PUBLIC heyaki::client)
heyaki_configure_target(heyaki_services)

# M10-09: optional SOCKS5 CONNECT frontend. A convenience LEAF outside the
# core dependency closure (nothing in heyaki_client references it): apps
# link it only when they expose a SOCKS entry point. Uses the public Node
# API plus the in-repo runtime accessor for the executor-owned Asio
# executor — no private protocol.
add_library(heyaki_socks src/socks/socks_frontend.cpp)
add_library(heyaki::socks ALIAS heyaki_socks)
set_target_properties(heyaki_socks PROPERTIES EXPORT_NAME socks
  OUTPUT_NAME heyaki_socks)
target_compile_features(heyaki_socks PUBLIC cxx_std_20)
target_include_directories(heyaki_socks PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src/socks")
target_link_libraries(heyaki_socks
  PUBLIC heyaki::client executor::executor)
heyaki_configure_target(heyaki_socks)
heyaki_target_use_pinned_boost_beast(heyaki_socks)
heyaki_enable_executor_exception_adapter_source(src/socks/socks_frontend.cpp)

add_library(heyaki_transport_webrtc
  src/transport/webrtc/module.cpp
  src/transport/webrtc/webrtc_transport_session.cpp)
add_library(heyaki::transport_webrtc ALIAS heyaki_transport_webrtc)
set_target_properties(heyaki_transport_webrtc PROPERTIES
  EXPORT_NAME transport_webrtc
  OUTPUT_NAME heyaki_transport_webrtc)
target_compile_features(heyaki_transport_webrtc PUBLIC cxx_std_20)
target_include_directories(heyaki_transport_webrtc PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src/transport")
target_include_directories(heyaki_transport_webrtc SYSTEM PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libdatachannel/include")
target_link_libraries(heyaki_transport_webrtc PRIVATE executor::executor heyaki::core)
if(WIN32)
  target_link_libraries(heyaki_transport_webrtc PRIVATE
    $<BUILD_INTERFACE:LibDataChannel::LibDataChannelStatic>
    $<INSTALL_INTERFACE:LibDataChannel::LibDataChannel>)
else()
  target_link_libraries(heyaki_transport_webrtc PRIVATE
    LibDataChannel::LibDataChannel)
endif()
heyaki_configure_target(heyaki_transport_webrtc)
heyaki_enable_executor_exception_adapter_source(
  src/transport/webrtc/webrtc_transport_session.cpp)

# Node owns the v1 connection assembly and instantiates the only shipped data-plane
# backend through its internal SPI.
target_link_libraries(heyaki_client PRIVATE heyaki_transport_webrtc)

add_library(heyaki_relay
  src/relay/relay_config.cpp
  src/relay/relay_database.cpp
  src/relay/relay_endpoint_directory.cpp
  src/relay/relay_enrollment_service.cpp
  src/relay/relay_login_service.cpp
  src/relay/relay_lease_table.cpp
  src/relay/relay_log.cpp
  src/relay/relay_metrics.cpp
  src/relay/relay_rate_limiter.cpp
  src/relay/relay_server.cpp
  src/relay/relay_turn_credentials.cpp)
add_library(heyaki::relay ALIAS heyaki_relay)
target_compile_features(heyaki_relay PUBLIC cxx_std_20)
target_include_directories(heyaki_relay
  PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/relay>"
  PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(heyaki_relay
  PUBLIC heyaki::client
  PRIVATE executor::executor heyaki::sodium heyaki::sqlite OpenSSL::SSL OpenSSL::Crypto)
heyaki_target_use_pinned_boost_beast(heyaki_relay)
heyaki_configure_target(heyaki_relay)
heyaki_enable_executor_exception_adapter_source(src/relay/relay_server.cpp)
if(MSVC)
  set_source_files_properties(
    src/client/node.cpp
    src/client/relay_wss_client.cpp
    src/relay/relay_database.cpp
    src/relay/relay_endpoint.cpp
    src/relay/relay_enrollment.cpp
    src/relay/relay_login.cpp
    src/relay/relay_server.cpp
    PROPERTIES COMPILE_OPTIONS "/bigobj")
endif()

set(HEYAKI_INSTALL_TARGETS
  heyaki_sodium
  heyaki_blake3
  heyaki_sqlite
  heyaki_core
  heyaki_profile
  heyaki_client
  heyaki_services
  heyaki_transport_webrtc)

if(HEYAKI_BUILD_APPS)
  add_executable(heyaki-relay apps/relay/main.cpp)
  target_link_libraries(heyaki-relay PRIVATE heyaki::relay executor::executor)
  heyaki_configure_target(heyaki-relay)

  add_library(heyaki_tui_setup STATIC
    apps/tui/device_view.cpp
    apps/tui/local_setup.cpp)
  target_include_directories(heyaki_tui_setup PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/apps/tui")
  target_link_libraries(heyaki_tui_setup PUBLIC heyaki::client heyaki::profile)
  heyaki_configure_target(heyaki_tui_setup)

  add_executable(heyaki-tui apps/tui/main.cpp)
  target_link_libraries(heyaki-tui PRIVATE
    heyaki_tui_setup heyaki::services heyaki::socks executor::executor)
  heyaki_target_use_pinned_boost_beast(heyaki-tui)
  heyaki_configure_target(heyaki-tui)
  heyaki_enable_executor_exception_adapter_source(apps/tui/main.cpp)

  add_executable(heyaki-m2-profile-demo apps/demo/m2_profile_demo.cpp)
  target_link_libraries(heyaki-m2-profile-demo PRIVATE heyaki::profile)
  heyaki_configure_target(heyaki-m2-profile-demo)

  add_executable(heyaki-m3b-relay-demo apps/demo/m3b_relay_demo.cpp)
  target_link_libraries(heyaki-m3b-relay-demo PRIVATE heyaki::relay executor::executor)
  heyaki_configure_target(heyaki-m3b-relay-demo)
  heyaki_enable_executor_exception_adapter_source(apps/demo/m3b_relay_demo.cpp)

  add_executable(heyaki-m6-message-rpc-demo apps/demo/m6_message_rpc_demo.cpp)
  target_link_libraries(heyaki-m6-message-rpc-demo PRIVATE heyaki::client executor::executor)
  heyaki_configure_target(heyaki-m6-message-rpc-demo)
  heyaki_enable_executor_exception_adapter_source(apps/demo/m6_message_rpc_demo.cpp)

  add_executable(heyaki-m7-data-demo apps/demo/m7_data_demo.cpp)
  target_link_libraries(heyaki-m7-data-demo PRIVATE heyaki::client executor::executor)
  heyaki_configure_target(heyaki-m7-data-demo)
  heyaki_enable_executor_exception_adapter_source(apps/demo/m7_data_demo.cpp)

  add_executable(heyaki-m4-matrix-node apps/demo/m4_matrix_node.cpp)
  target_link_libraries(heyaki-m4-matrix-node
    PRIVATE heyaki::client heyaki::profile executor::executor OpenSSL::SSL OpenSSL::Crypto)
  heyaki_target_use_pinned_boost_asio(heyaki-m4-matrix-node)
  heyaki_configure_target(heyaki-m4-matrix-node)
  heyaki_enable_executor_exception_adapter_source(apps/demo/m4_matrix_node.cpp)

  # M9-07: host-local TURN/UDP server (libjuice embedded TURN) for matrix
  # scenarios on hosts without coturn (Windows CI, self-hosted cross-OS
  # fleets). Static target: the helper must not drag the libjuice DLL
  # dependency into every consumer of the install tree.
  # M9-19: with the libnice backend libdatachannel no longer adds its vendored
  # libjuice subdirectory, so build it here for this helper only (EXCLUDE_FROM
  # _ALL keeps it out of default builds). The helper stays TURN/UDP: TURN/TCP
  # and TURN/TLS scenarios run against coturn.
  if(NOT TARGET LibJuice::LibJuiceStatic)
    add_subdirectory(third_party/libdatachannel/deps/libjuice libjuice-test-server
      EXCLUDE_FROM_ALL)
  endif()
  add_executable(heyaki-test-turn-server apps/demo/test_turn_server.cpp)
  target_link_libraries(heyaki-test-turn-server PRIVATE LibJuice::LibJuiceStatic)
  heyaki_configure_target(heyaki-test-turn-server)

  # M9-14: release artifact signing. Single-shot synchronous CLI over the
  # pinned libsodium (Ed25519 manifest signatures); no executor context by
  # design.
  add_executable(heyaki-release-sign apps/release/heyaki_release_sign.cpp)
  target_link_libraries(heyaki-release-sign PRIVATE heyaki::sodium)
  heyaki_configure_target(heyaki-release-sign)

  list(APPEND HEYAKI_INSTALL_TARGETS heyaki-relay heyaki-tui heyaki-m2-profile-demo
       heyaki-m3b-relay-demo heyaki-m6-message-rpc-demo heyaki-m4-matrix-node
       heyaki-test-turn-server heyaki-m7-data-demo heyaki-release-sign)
endif()

heyaki_add_developer_targets()
heyaki_generate_supply_chain_files(
  "${CMAKE_CURRENT_BINARY_DIR}/supply-chain"
  HEYAKI_SBOM_FILE
  HEYAKI_LICENSE_MANIFEST_FILE)

if(BUILD_TESTING)
  add_subdirectory(tests)
endif()

install(TARGETS ${HEYAKI_INSTALL_TARGETS}
  EXPORT heyakiTargets
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(DIRECTORY include/ DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(DIRECTORY proto/ DESTINATION "${CMAKE_INSTALL_DATADIR}/heyaki/proto"
  FILES_MATCHING PATTERN "*.proto")
install(FILES "${HEYAKI_GENERATED_DIR}/heyaki/detail/build_config.hpp"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/heyaki/detail")
install(FILES "${HEYAKI_SBOM_FILE}" "${HEYAKI_LICENSE_MANIFEST_FILE}"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/heyaki/supply-chain")
install(FILES
  LICENSE
  DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/heyaki")
install(FILES
  docs/supply-chain/m1-libsodium-sha256-notices.md
  docs/supply-chain/boost-software-license-1.0.txt
  DESTINATION "${CMAKE_INSTALL_DATADIR}/heyaki/supply-chain")
# M9-17: the release tree carries the example coturn deployment baseline and
# every third-party license text referenced by the license lock, so the
# package is self-contained for compliance review without the source tree.
install(FILES
  deploy/coturn/turnserver.conf
  deploy/coturn/docker-compose.yml
  deploy/coturn/heyaki-turn.env.example
  deploy/coturn/README.md
  DESTINATION "${CMAKE_INSTALL_DATADIR}/heyaki/coturn")
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/licenses.lock"
  heyaki_license_lock_lines)
set(heyaki_license_file_count 0)
foreach(heyaki_license_line IN LISTS heyaki_license_lock_lines)
  if(heyaki_license_line STREQUAL "" OR heyaki_license_line MATCHES "^#")
    continue()
  endif()
  string(REPLACE "|" ";" heyaki_license_fields "${heyaki_license_line}")
  list(LENGTH heyaki_license_fields heyaki_license_field_count)
  if(NOT heyaki_license_field_count EQUAL 3)
    message(FATAL_ERROR "Invalid license lock entry: ${heyaki_license_line}")
  endif()
  list(GET heyaki_license_fields 0 heyaki_license_name)
  list(GET heyaki_license_fields 2 heyaki_license_path)
  if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${heyaki_license_path}")
    message(FATAL_ERROR
      "License file for ${heyaki_license_name} does not exist: ${heyaki_license_path}")
  endif()
  get_filename_component(heyaki_license_basename "${heyaki_license_path}" NAME)
  install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/${heyaki_license_path}"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/heyaki/licenses"
    RENAME "${heyaki_license_name}-${heyaki_license_basename}")
  math(EXPR heyaki_license_file_count "${heyaki_license_file_count} + 1")
endforeach()
message(STATUS "Packaging ${heyaki_license_file_count} third-party license texts")
# M9-19/M9-17: libnice builds dynamically link LGPL-2.1 system libraries;
# ship the license text and the compliance notice with the artifacts.
if(HEYAKI_ICE_BACKEND STREQUAL "nice")
  install(FILES
    deploy/licenses/lgpl-2.1.txt
    deploy/licenses/NOTICE-libnice.md
    DESTINATION "${CMAKE_INSTALL_DATADIR}/heyaki/licenses")
endif()

set(HEYAKI_CMAKE_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/heyaki")
# M9-19: with the libnice backend the installed LibDataChannel target carries
# $<LINK_ONLY:LibNice::LibNice> in its link interface (upstream config does
# not find libnice for consumers), so the heyaki package must define that
# target first. Reuse the pinned dependency's own find modules so the consumer
# probe matches the build probe.
if(HEYAKI_ICE_BACKEND STREQUAL "nice")
  install(FILES
    third_party/libdatachannel/cmake/Modules/FindLibNice.cmake
    third_party/libdatachannel/cmake/Modules/FindGLIB.cmake
    DESTINATION "${HEYAKI_CMAKE_INSTALL_DIR}/modules")
endif()
configure_package_config_file(
  cmake/heyakiConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/heyakiConfig.cmake"
  INSTALL_DESTINATION "${HEYAKI_CMAKE_INSTALL_DIR}")
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/heyakiConfigVersion.cmake"
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion)
install(EXPORT heyakiTargets
  FILE heyakiTargets.cmake
  NAMESPACE heyaki::
  DESTINATION "${HEYAKI_CMAKE_INSTALL_DIR}")
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/heyakiConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/heyakiConfigVersion.cmake"
  DESTINATION "${HEYAKI_CMAKE_INSTALL_DIR}")

if(HEYAKI_AUTO_INSTALL)
  add_custom_target(heyaki-deploy ALL
    COMMAND "${CMAKE_COMMAND}" --install "${CMAKE_BINARY_DIR}"
      --config "$<CONFIG>"
      --prefix "${HEYAKI_INSTALL_PREFIX}"
    DEPENDS ${HEYAKI_INSTALL_TARGETS}
    USES_TERMINAL
    COMMENT "Installing Heyaki into ${HEYAKI_INSTALL_PREFIX}")
  if(TARGET heyaki-sbom)
    add_dependencies(heyaki-deploy heyaki-sbom)
  endif()
endif()

# M9-17: manifest-driven uninstall (see cmake/cmake_uninstall.cmake for the
# contract). The packaging test exercises it against a scratch prefix.
add_custom_target(uninstall
  COMMAND "${CMAKE_COMMAND}"
    "-DHEYAKI_INSTALL_MANIFEST=${CMAKE_BINARY_DIR}/install_manifest.txt"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake"
  USES_TERMINAL
  COMMENT "Uninstalling Heyaki (files recorded in install_manifest.txt)")
