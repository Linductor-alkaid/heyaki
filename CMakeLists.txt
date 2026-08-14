cmake_minimum_required(VERSION 3.25)

project(
  heyaki
  VERSION 0.0.0
  DESCRIPTION "Device-to-device communication infrastructure"
  LANGUAGES C CXX)

include(CTest)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(HEYAKI_BUILD_APPS "Build heyaki-relay and heyaki-tui" ON)
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

set(HEYAKI_SANITIZER "none" CACHE STRING "Sanitizer: none, address, undefined, or thread")
set_property(CACHE HEYAKI_SANITIZER PROPERTY STRINGS none address undefined thread)
set(HEYAKI_BUILD_COMMIT "" CACHE STRING "Override the source commit reported by build_info()")

set(HEYAKI_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated" CACHE PATH
    "Generated protocol and build metadata directory")
set(HEYAKI_TEST_STATE_DIR "${CMAKE_CURRENT_BINARY_DIR}/test-state" CACHE PATH
    "Temporary profiles, credentials, and databases used by tests")
set(HEYAKI_FUZZ_CORPUS_DIR "${CMAKE_CURRENT_BINARY_DIR}/fuzz-corpus" CACHE PATH
    "Generated fuzz corpus directory")

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
include(HeyakiVersion)

if(HEYAKI_VERIFY_DEPENDENCIES)
  heyaki_verify_dependencies()
endif()

heyaki_resolve_build_commit(HEYAKI_RESOLVED_BUILD_COMMIT)
set(HEYAKI_PROTOCOL_VERSION_MAJOR 1)
set(HEYAKI_PROTOCOL_VERSION_MINOR 0)
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
  src/core/ids.cpp
  src/core/limits.cpp
  src/core/operation.cpp
  src/core/protocol.cpp
  src/core/security.cpp
  src/core/signing.cpp
  src/core/sodium_memzero.cpp
  src/core/version.cpp
  src/core/wire.cpp
  third_party/libsodium/src/libsodium/crypto_hash/sha256/cp/hash_sha256_cp.c
  third_party/libsodium/src/libsodium/crypto_hash/sha256/hash_sha256.c)
add_library(heyaki::core ALIAS heyaki_core)
set_target_properties(heyaki_core PROPERTIES EXPORT_NAME core OUTPUT_NAME heyaki_core)
target_compile_features(heyaki_core PUBLIC cxx_std_20)
target_compile_features(heyaki_core PRIVATE c_std_11)
target_include_directories(heyaki_core
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<BUILD_INTERFACE:${HEYAKI_GENERATED_DIR}>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/src/libsodium/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/src/libsodium/include/sodium")
# M1 needs only DeviceId SHA-256 derivation. Compile the pinned libsodium implementation with
# private symbol names; M2 can link the full library without duplicate public sodium symbols.
target_compile_definitions(heyaki_core PRIVATE
  SODIUM_STATIC
  CONFIGURED=1
  crypto_hash_sha256=heyaki_crypto_hash_sha256
  crypto_hash_sha256_bytes=heyaki_crypto_hash_sha256_bytes
  crypto_hash_sha256_final=heyaki_crypto_hash_sha256_final
  crypto_hash_sha256_init=heyaki_crypto_hash_sha256_init
  crypto_hash_sha256_statebytes=heyaki_crypto_hash_sha256_statebytes
  crypto_hash_sha256_update=heyaki_crypto_hash_sha256_update
  sodium_memzero=heyaki_sodium_memzero)
heyaki_configure_target(heyaki_core)

add_library(heyaki_profile src/profile/module.cpp)
add_library(heyaki::profile ALIAS heyaki_profile)
set_target_properties(heyaki_profile PROPERTIES EXPORT_NAME profile OUTPUT_NAME heyaki_profile)
target_compile_features(heyaki_profile PUBLIC cxx_std_20)
target_link_libraries(heyaki_profile PUBLIC heyaki::core)
heyaki_configure_target(heyaki_profile)

add_library(heyaki_client src/client/module.cpp)
add_library(heyaki::client ALIAS heyaki_client)
set_target_properties(heyaki_client PROPERTIES EXPORT_NAME client OUTPUT_NAME heyaki_client)
target_compile_features(heyaki_client PUBLIC cxx_std_20)
target_link_libraries(heyaki_client PUBLIC heyaki::profile)
heyaki_configure_target(heyaki_client)

add_library(heyaki_services src/services/module.cpp)
add_library(heyaki::services ALIAS heyaki_services)
set_target_properties(heyaki_services PROPERTIES EXPORT_NAME services OUTPUT_NAME heyaki_services)
target_compile_features(heyaki_services PUBLIC cxx_std_20)
target_link_libraries(heyaki_services PUBLIC heyaki::client)
heyaki_configure_target(heyaki_services)

add_library(heyaki_transport_webrtc src/transport/webrtc/module.cpp)
add_library(heyaki::transport_webrtc ALIAS heyaki_transport_webrtc)
set_target_properties(heyaki_transport_webrtc PROPERTIES
  EXPORT_NAME transport_webrtc
  OUTPUT_NAME heyaki_transport_webrtc)
target_compile_features(heyaki_transport_webrtc PUBLIC cxx_std_20)
target_link_libraries(heyaki_transport_webrtc PRIVATE heyaki::core)
heyaki_configure_target(heyaki_transport_webrtc)

set(HEYAKI_INSTALL_TARGETS
  heyaki_core
  heyaki_profile
  heyaki_client
  heyaki_services
  heyaki_transport_webrtc)

if(HEYAKI_BUILD_APPS)
  add_executable(heyaki-relay apps/relay/main.cpp)
  target_link_libraries(heyaki-relay PRIVATE heyaki::core)
  heyaki_configure_target(heyaki-relay)

  add_executable(heyaki-tui apps/tui/main.cpp)
  target_link_libraries(heyaki-tui PRIVATE heyaki::services)
  heyaki_configure_target(heyaki-tui)

  list(APPEND HEYAKI_INSTALL_TARGETS heyaki-relay heyaki-tui)
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
install(FILES docs/supply-chain/m1-libsodium-sha256-notices.md
  DESTINATION "${CMAKE_INSTALL_DATADIR}/heyaki/supply-chain")

set(HEYAKI_CMAKE_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/heyaki")
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
