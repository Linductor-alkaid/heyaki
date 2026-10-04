include_guard(GLOBAL)

function(heyaki_visual_studio_platform_to_vcvars_arch output_variable platform_name)
  set(normalized_platform "${platform_name}")
  string(REGEX REPLACE ",.*$" "" normalized_platform "${normalized_platform}")
  string(STRIP "${normalized_platform}" normalized_platform)
  string(TOLOWER "${normalized_platform}" normalized_platform)

  if(normalized_platform STREQUAL "win32" OR normalized_platform STREQUAL "x86")
    set(vcvars_arch x86)
  elseif(normalized_platform STREQUAL "x64" OR normalized_platform STREQUAL "amd64")
    set(vcvars_arch x64)
  elseif(normalized_platform STREQUAL "arm")
    set(vcvars_arch arm)
  elseif(normalized_platform STREQUAL "arm64")
    set(vcvars_arch arm64)
  else()
    message(FATAL_ERROR
      "Unsupported Visual Studio platform for SQLite generation: ${platform_name}")
  endif()

  set(${output_variable} "${vcvars_arch}" PARENT_SCOPE)
endfunction()

function(heyaki_write_sqlite_msvc_generation_script
    output_file visual_studio_root vcvars_arch sqlite_source_dir)
  set(visual_studio_root_native "${visual_studio_root}")
  set(sqlite_source_dir_native "${sqlite_source_dir}")
  set(sqlite_makefile_native "${sqlite_source_dir}/Makefile.msc")
  cmake_path(NATIVE_PATH visual_studio_root_native NORMALIZE visual_studio_root_native)
  cmake_path(NATIVE_PATH sqlite_source_dir_native NORMALIZE sqlite_source_dir_native)
  cmake_path(NATIVE_PATH sqlite_makefile_native NORMALIZE sqlite_makefile_native)
  foreach(path_variable IN ITEMS
      visual_studio_root_native sqlite_source_dir_native sqlite_makefile_native)
    string(REPLACE "'" "''" ${path_variable} "${${path_variable}}")
  endforeach()
  file(WRITE "${output_file}"
    "$ErrorActionPreference = 'Stop'\n"
    "$vsInstallPath = '${visual_studio_root_native}'\n"
    "$devShellModule = Join-Path $vsInstallPath "
      "'Common7\\Tools\\Microsoft.VisualStudio.DevShell.dll'\n"
    "Write-Host '[heyaki-sqlite] initializing MSVC environment'\n"
    "Import-Module $devShellModule\n"
    "Enter-VsDevShell -VsInstallPath $vsInstallPath -SkipAutomaticLocation "
      "-DevCmdArguments '-arch=${vcvars_arch} -host_arch=x64'\n"
    "Write-Host '[heyaki-sqlite] generating SQLite amalgamation'\n"
    "& nmake.exe /NOLOGO /f '${sqlite_makefile_native}' "
      "'TOP=${sqlite_source_dir_native}' sqlite3.c sqlite3.h\n"
    "exit $LASTEXITCODE\n")
endfunction()

function(heyaki_add_pinned_boost_asio)
  set(boost_modules asio system config assert throw_exception predef winapi)
  set(boost_include_dirs)
  foreach(boost_module IN LISTS boost_modules)
    set(boost_root "${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost-${boost_module}")
    if(NOT EXISTS "${boost_root}/include/boost")
      message(FATAL_ERROR
        "Pinned Boost.${boost_module} checkout is missing. Run "
        "`scripts/fetch_third_party.sh boost-${boost_module}`.")
    endif()
    list(APPEND boost_include_dirs "${boost_root}/include")
  endforeach()
  set(HEYAKI_BOOST_ASIO_INCLUDE_DIRS "${boost_include_dirs}" PARENT_SCOPE)
  find_package(Threads REQUIRED)
endfunction()

function(heyaki_add_pinned_boost_beast)
  set(boost_modules beast bind container_hash core describe endian intrusive io move mp11
                    optional preprocessor smart_ptr static_assert static_string type_index
                    type_traits utility)
  set(boost_include_dirs)
  foreach(boost_module IN LISTS boost_modules)
    set(boost_root "${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost-${boost_module}")
    if(NOT EXISTS "${boost_root}/include/boost")
      message(FATAL_ERROR
        "Pinned Boost.${boost_module} checkout is missing. Run "
        "`scripts/fetch_third_party.sh boost-${boost_module}`.")
    endif()
    list(APPEND boost_include_dirs "${boost_root}/include")
  endforeach()
  set(HEYAKI_BOOST_BEAST_INCLUDE_DIRS "${boost_include_dirs}" PARENT_SCOPE)
endfunction()

function(heyaki_apply_pinned_boost_definitions target_name)
  target_compile_definitions(${target_name} PRIVATE
    BOOST_ERROR_CODE_HEADER_ONLY
    BOOST_SYSTEM_NO_DEPRECATED
    BOOST_ASIO_DISABLE_BOOST_DATE_TIME
    BOOST_ASIO_DISABLE_BOOST_ALIGN
    "$<$<PLATFORM_ID:Windows>:_WIN32_WINNT=0x0A00>")
  target_link_libraries(${target_name} PRIVATE Threads::Threads)
endfunction()

function(heyaki_target_use_pinned_boost_asio target_name)
  target_include_directories(${target_name} SYSTEM PRIVATE ${HEYAKI_BOOST_ASIO_INCLUDE_DIRS})
  heyaki_apply_pinned_boost_definitions(${target_name})
endfunction()

function(heyaki_target_use_pinned_boost_beast target_name)
  target_include_directories(${target_name} SYSTEM PRIVATE
    ${HEYAKI_BOOST_BEAST_INCLUDE_DIRS}
    ${HEYAKI_BOOST_ASIO_INCLUDE_DIRS})
  heyaki_apply_pinned_boost_definitions(${target_name})
endfunction()

function(heyaki_add_vendored_sodium)
  if(TARGET heyaki_sodium)
    return()
  endif()

  set(sodium_root "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/src/libsodium")
  set(sodium_generated_include "${CMAKE_CURRENT_BINARY_DIR}/vendored/libsodium/include")
  file(MAKE_DIRECTORY "${sodium_generated_include}/sodium")
  set(VERSION 1.0.20)
  set(SODIUM_LIBRARY_VERSION_MAJOR 26)
  set(SODIUM_LIBRARY_VERSION_MINOR 2)
  configure_file(
    "${sodium_root}/include/sodium/version.h.in"
    "${sodium_generated_include}/sodium/version.h"
    @ONLY)
  add_library(heyaki_sodium STATIC
    "${sodium_root}/crypto_aead/aegis128l/aead_aegis128l.c"
    "${sodium_root}/crypto_aead/aegis128l/aegis128l_aesni.c"
    "${sodium_root}/crypto_aead/aegis128l/aegis128l_soft.c"
    "${sodium_root}/crypto_aead/aegis256/aead_aegis256.c"
    "${sodium_root}/crypto_aead/aegis256/aegis256_aesni.c"
    "${sodium_root}/crypto_aead/aegis256/aegis256_soft.c"
    "${sodium_root}/crypto_aead/aes256gcm/aead_aes256gcm.c"
    "${sodium_root}/crypto_aead/aes256gcm/aesni/aead_aes256gcm_aesni.c"
    "${sodium_root}/crypto_aead/chacha20poly1305/aead_chacha20poly1305.c"
    "${sodium_root}/crypto_aead/xchacha20poly1305/aead_xchacha20poly1305.c"
    "${sodium_root}/crypto_auth/crypto_auth.c"
    "${sodium_root}/crypto_auth/hmacsha256/auth_hmacsha256.c"
    "${sodium_root}/crypto_auth/hmacsha512/auth_hmacsha512.c"
    "${sodium_root}/crypto_auth/hmacsha512256/auth_hmacsha512256.c"
    "${sodium_root}/crypto_box/crypto_box.c"
    "${sodium_root}/crypto_box/crypto_box_easy.c"
    "${sodium_root}/crypto_box/crypto_box_seal.c"
    "${sodium_root}/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305.c"
    "${sodium_root}/crypto_core/ed25519/ref10/ed25519_ref10.c"
    "${sodium_root}/crypto_core/hchacha20/core_hchacha20.c"
    "${sodium_root}/crypto_core/hsalsa20/core_hsalsa20.c"
    "${sodium_root}/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c"
    "${sodium_root}/crypto_core/salsa/ref/core_salsa_ref.c"
    "${sodium_root}/crypto_core/softaes/softaes.c"
    "${sodium_root}/crypto_generichash/crypto_generichash.c"
    "${sodium_root}/crypto_generichash/blake2b/generichash_blake2.c"
    "${sodium_root}/crypto_generichash/blake2b/ref/blake2b-compress-avx2.c"
    "${sodium_root}/crypto_generichash/blake2b/ref/blake2b-compress-ref.c"
    "${sodium_root}/crypto_generichash/blake2b/ref/blake2b-compress-sse41.c"
    "${sodium_root}/crypto_generichash/blake2b/ref/blake2b-compress-ssse3.c"
    "${sodium_root}/crypto_generichash/blake2b/ref/blake2b-ref.c"
    "${sodium_root}/crypto_generichash/blake2b/ref/generichash_blake2b.c"
    "${sodium_root}/crypto_hash/crypto_hash.c"
    "${sodium_root}/crypto_hash/sha256/cp/hash_sha256_cp.c"
    "${sodium_root}/crypto_hash/sha256/hash_sha256.c"
    "${sodium_root}/crypto_hash/sha512/cp/hash_sha512_cp.c"
    "${sodium_root}/crypto_hash/sha512/hash_sha512.c"
    "${sodium_root}/crypto_kdf/blake2b/kdf_blake2b.c"
    "${sodium_root}/crypto_kdf/crypto_kdf.c"
    "${sodium_root}/crypto_kdf/hkdf/kdf_hkdf_sha256.c"
    "${sodium_root}/crypto_kdf/hkdf/kdf_hkdf_sha512.c"
    "${sodium_root}/crypto_kx/crypto_kx.c"
    "${sodium_root}/crypto_onetimeauth/crypto_onetimeauth.c"
    "${sodium_root}/crypto_onetimeauth/poly1305/donna/poly1305_donna.c"
    "${sodium_root}/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c"
    "${sodium_root}/crypto_onetimeauth/poly1305/sse2/poly1305_sse2.c"
    "${sodium_root}/crypto_pwhash/argon2/argon2-core.c"
    "${sodium_root}/crypto_pwhash/argon2/argon2-encoding.c"
    "${sodium_root}/crypto_pwhash/argon2/argon2-fill-block-avx2.c"
    "${sodium_root}/crypto_pwhash/argon2/argon2-fill-block-avx512f.c"
    "${sodium_root}/crypto_pwhash/argon2/argon2-fill-block-ref.c"
    "${sodium_root}/crypto_pwhash/argon2/argon2-fill-block-ssse3.c"
    "${sodium_root}/crypto_pwhash/argon2/argon2.c"
    "${sodium_root}/crypto_pwhash/argon2/blake2b-long.c"
    "${sodium_root}/crypto_pwhash/argon2/pwhash_argon2i.c"
    "${sodium_root}/crypto_pwhash/argon2/pwhash_argon2id.c"
    "${sodium_root}/crypto_pwhash/crypto_pwhash.c"
    "${sodium_root}/crypto_scalarmult/crypto_scalarmult.c"
    "${sodium_root}/crypto_scalarmult/curve25519/ref10/x25519_ref10.c"
    "${sodium_root}/crypto_scalarmult/curve25519/scalarmult_curve25519.c"
    "${sodium_root}/crypto_secretbox/crypto_secretbox.c"
    "${sodium_root}/crypto_secretbox/crypto_secretbox_easy.c"
    "${sodium_root}/crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305.c"
    "${sodium_root}/crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c"
    "${sodium_root}/crypto_shorthash/crypto_shorthash.c"
    "${sodium_root}/crypto_shorthash/siphash24/ref/shorthash_siphash24_ref.c"
    "${sodium_root}/crypto_shorthash/siphash24/shorthash_siphash24.c"
    "${sodium_root}/crypto_sign/crypto_sign.c"
    "${sodium_root}/crypto_sign/ed25519/ref10/keypair.c"
    "${sodium_root}/crypto_sign/ed25519/ref10/open.c"
    "${sodium_root}/crypto_sign/ed25519/ref10/sign.c"
    "${sodium_root}/crypto_sign/ed25519/sign_ed25519.c"
    "${sodium_root}/crypto_stream/chacha20/dolbeau/chacha20_dolbeau-avx2.c"
    "${sodium_root}/crypto_stream/chacha20/dolbeau/chacha20_dolbeau-ssse3.c"
    "${sodium_root}/crypto_stream/chacha20/ref/chacha20_ref.c"
    "${sodium_root}/crypto_stream/chacha20/stream_chacha20.c"
    "${sodium_root}/crypto_stream/crypto_stream.c"
    "${sodium_root}/crypto_stream/salsa20/ref/salsa20_ref.c"
    "${sodium_root}/crypto_stream/salsa20/stream_salsa20.c"
    "${sodium_root}/crypto_stream/salsa20/xmm6int/salsa20_xmm6int-avx2.c"
    "${sodium_root}/crypto_stream/salsa20/xmm6int/salsa20_xmm6int-sse2.c"
    "${sodium_root}/crypto_stream/xsalsa20/stream_xsalsa20.c"
    "${sodium_root}/crypto_verify/verify.c"
    "${sodium_root}/randombytes/randombytes.c"
    "${sodium_root}/randombytes/sysrandom/randombytes_sysrandom.c"
    "${sodium_root}/sodium/codecs.c"
    "${sodium_root}/sodium/core.c"
    "${sodium_root}/sodium/runtime.c"
    "${sodium_root}/sodium/utils.c"
    "${sodium_root}/sodium/version.c")
  add_library(heyaki::sodium ALIAS heyaki_sodium)
  set_target_properties(heyaki_sodium PROPERTIES
    EXPORT_NAME sodium
    OUTPUT_NAME heyaki_sodium)
  target_include_directories(heyaki_sodium
    PUBLIC "$<BUILD_INTERFACE:${sodium_generated_include}>"
    PUBLIC "$<BUILD_INTERFACE:${sodium_root}/include>"
    PUBLIC "$<BUILD_INTERFACE:${sodium_root}/include/sodium>"
    PRIVATE "${sodium_generated_include}/sodium" "${sodium_root}/include/sodium")
  target_compile_definitions(heyaki_sodium
    PUBLIC SODIUM_STATIC
    PRIVATE CONFIGURED=1)
  set_target_properties(heyaki_sodium PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON)

  if(WIN32)
    target_link_libraries(heyaki_sodium PRIVATE advapi32)
  else()
    find_package(Threads REQUIRED)
    target_compile_definitions(heyaki_sodium PRIVATE HAVE_PTHREAD=1 HAVE_ATOMIC_OPS=1)
    target_link_libraries(heyaki_sodium PRIVATE Threads::Threads)
  endif()

  if(NOT HEYAKI_SANITIZER STREQUAL "none" AND
     CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    if(HEYAKI_SANITIZER STREQUAL "address")
      set(sodium_sanitizer_flag -fsanitize=address)
    elseif(HEYAKI_SANITIZER STREQUAL "undefined")
      set(sodium_sanitizer_flag -fsanitize=undefined)
    elseif(HEYAKI_SANITIZER STREQUAL "thread")
      set(sodium_sanitizer_flag -fsanitize=thread)
    endif()
    target_compile_options(heyaki_sodium PRIVATE
      "${sodium_sanitizer_flag}" -fno-omit-frame-pointer)
    target_link_options(heyaki_sodium PUBLIC
      "${sodium_sanitizer_flag}" -fno-omit-frame-pointer)
  endif()
endfunction()

# BLAKE3 (M7 file transfer digests). Built from the pinned checkout's
# portable C core only: the dispatcher's SIMD/NEON branches are disabled via
# BLAKE3_NO_* so no per-file architecture flags or assembly sources are
# needed and sanitizer builds stay deterministic on every supported
# platform. The portable implementation still exceeds the v1 WebRTC data
# path's throughput budget by an order of magnitude.
function(heyaki_add_vendored_blake3)
  if(TARGET heyaki_blake3)
    return()
  endif()

  set(blake3_root "${CMAKE_CURRENT_SOURCE_DIR}/third_party/blake3/c")
  add_library(heyaki_blake3 STATIC
    "${blake3_root}/blake3.c"
    "${blake3_root}/blake3_dispatch.c"
    "${blake3_root}/blake3_portable.c")
  add_library(heyaki::blake3 ALIAS heyaki_blake3)
  set_target_properties(heyaki_blake3 PROPERTIES
    EXPORT_NAME blake3
    OUTPUT_NAME heyaki_blake3)
  target_include_directories(heyaki_blake3
    PUBLIC "$<BUILD_INTERFACE:${blake3_root}>")
  target_compile_definitions(heyaki_blake3 PRIVATE
    BLAKE3_NO_SSE2 BLAKE3_NO_SSE41 BLAKE3_NO_AVX2 BLAKE3_NO_AVX512 BLAKE3_NO_NEON)
  set_target_properties(heyaki_blake3 PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON)

  if(NOT HEYAKI_SANITIZER STREQUAL "none" AND
     CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    if(HEYAKI_SANITIZER STREQUAL "address")
      set(blake3_sanitizer_flag -fsanitize=address)
    elseif(HEYAKI_SANITIZER STREQUAL "undefined")
      set(blake3_sanitizer_flag -fsanitize=undefined)
    elseif(HEYAKI_SANITIZER STREQUAL "thread")
      set(blake3_sanitizer_flag -fsanitize=thread)
    endif()
    target_compile_options(heyaki_blake3 PRIVATE
      "${blake3_sanitizer_flag}" -fno-omit-frame-pointer)
    target_link_options(heyaki_blake3 PUBLIC
      "${blake3_sanitizer_flag}" -fno-omit-frame-pointer)
  endif()
endfunction()

function(heyaki_add_vendored_sqlite)
  if(TARGET heyaki_sqlite)
    return()
  endif()

  set(sqlite_source_dir "${CMAKE_CURRENT_SOURCE_DIR}/third_party/sqlite")
  set(sqlite_build_dir "${CMAKE_CURRENT_BINARY_DIR}/vendored/sqlite")
  set(sqlite_c "${sqlite_build_dir}/sqlite3.c")
  set(sqlite_h "${sqlite_build_dir}/sqlite3.h")
  file(MAKE_DIRECTORY "${sqlite_build_dir}")

  if(NOT EXISTS "${sqlite_c}" OR NOT EXISTS "${sqlite_h}")
    if(MSVC)
      find_program(heyaki_nmake_executable NAMES nmake NO_CACHE)
      if(heyaki_nmake_executable)
        execute_process(
          COMMAND "${heyaki_nmake_executable}"
            /NOLOGO
            /f "${sqlite_source_dir}/Makefile.msc"
            "TOP=${sqlite_source_dir}"
            sqlite3.c sqlite3.h
          WORKING_DIRECTORY "${sqlite_build_dir}"
          RESULT_VARIABLE sqlite_generate_result
          OUTPUT_VARIABLE sqlite_generate_stdout
          ERROR_VARIABLE sqlite_generate_stderr)
      elseif(CMAKE_GENERATOR MATCHES "^Visual Studio ")
        set(sqlite_dev_shell_module
          "${CMAKE_GENERATOR_INSTANCE}/Common7/Tools/Microsoft.VisualStudio.DevShell.dll")
        if(NOT CMAKE_GENERATOR_INSTANCE OR NOT EXISTS "${sqlite_dev_shell_module}")
          message(FATAL_ERROR
            "Could not locate Microsoft.VisualStudio.DevShell.dll for the selected "
            "Visual Studio instance: "
            "${CMAKE_GENERATOR_INSTANCE}")
        endif()

        set(sqlite_vs_platform "${CMAKE_GENERATOR_PLATFORM}")
        if(NOT sqlite_vs_platform AND DEFINED CMAKE_VS_PLATFORM_NAME)
          set(sqlite_vs_platform "${CMAKE_VS_PLATFORM_NAME}")
        endif()
        heyaki_visual_studio_platform_to_vcvars_arch(
          sqlite_vcvars_arch "${sqlite_vs_platform}")

        find_program(heyaki_powershell_executable
          NAMES pwsh.exe powershell.exe pwsh powershell NO_CACHE)
        if(NOT heyaki_powershell_executable)
          message(FATAL_ERROR
            "Could not locate PowerShell for SQLite generation")
        endif()

        set(sqlite_generate_script "${sqlite_build_dir}/generate-amalgamation.ps1")
        heyaki_write_sqlite_msvc_generation_script(
          "${sqlite_generate_script}"
          "${CMAKE_GENERATOR_INSTANCE}"
          "${sqlite_vcvars_arch}"
          "${sqlite_source_dir}")
        execute_process(
          COMMAND "${heyaki_powershell_executable}"
            -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass
            -File "${sqlite_generate_script}"
          WORKING_DIRECTORY "${sqlite_build_dir}"
          RESULT_VARIABLE sqlite_generate_result
          OUTPUT_VARIABLE sqlite_generate_stdout
          ERROR_VARIABLE sqlite_generate_stderr)
        if(NOT sqlite_generate_result EQUAL 0)
          file(READ "${sqlite_generate_script}" sqlite_generate_script_contents)
        endif()
      else()
        message(FATAL_ERROR
          "Could not locate nmake for SQLite generation. Configure from an MSVC developer "
          "environment or use a Visual Studio CMake generator.")
      endif()
    else()
      find_program(HEYAKI_MAKE_EXECUTABLE NAMES gmake make REQUIRED)
      execute_process(
        COMMAND "${sqlite_source_dir}/configure"
          --disable-shared --disable-readline
        WORKING_DIRECTORY "${sqlite_build_dir}"
        RESULT_VARIABLE sqlite_configure_result)
      if(NOT sqlite_configure_result EQUAL 0)
        message(FATAL_ERROR "Pinned SQLite configure failed: ${sqlite_configure_result}")
      endif()
      execute_process(
        COMMAND "${HEYAKI_MAKE_EXECUTABLE}" sqlite3.c sqlite3.h
        WORKING_DIRECTORY "${sqlite_build_dir}"
        RESULT_VARIABLE sqlite_generate_result)
    endif()
    if(NOT sqlite_generate_result EQUAL 0)
      message(FATAL_ERROR
        "Pinned SQLite amalgamation generation failed: ${sqlite_generate_result}\n"
        "stdout:\n${sqlite_generate_stdout}\n"
        "stderr:\n${sqlite_generate_stderr}\n"
        "script:\n${sqlite_generate_script_contents}")
    endif()
  endif()

  add_library(heyaki_sqlite STATIC "${sqlite_c}")
  add_library(heyaki::sqlite ALIAS heyaki_sqlite)
  set_target_properties(heyaki_sqlite PROPERTIES
    EXPORT_NAME sqlite
    OUTPUT_NAME heyaki_sqlite)
  target_include_directories(heyaki_sqlite
    PUBLIC "$<BUILD_INTERFACE:${sqlite_build_dir}>")
  target_compile_definitions(heyaki_sqlite PRIVATE
    SQLITE_DEFAULT_FOREIGN_KEYS=1
    SQLITE_DQS=0
    SQLITE_ENABLE_API_ARMOR=1
    SQLITE_OMIT_DEPRECATED=1
    SQLITE_OMIT_LOAD_EXTENSION=1
    SQLITE_THREADSAFE=1)
  set_target_properties(heyaki_sqlite PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON)
  if(NOT WIN32)
    target_link_libraries(heyaki_sqlite PRIVATE ${CMAKE_DL_LIBS})
  endif()

  if(NOT HEYAKI_SANITIZER STREQUAL "none" AND
     CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    if(HEYAKI_SANITIZER STREQUAL "address")
      set(sqlite_sanitizer_flag -fsanitize=address)
    elseif(HEYAKI_SANITIZER STREQUAL "undefined")
      set(sqlite_sanitizer_flag -fsanitize=undefined)
    elseif(HEYAKI_SANITIZER STREQUAL "thread")
      set(sqlite_sanitizer_flag -fsanitize=thread)
    endif()
    target_compile_options(heyaki_sqlite PRIVATE
      "${sqlite_sanitizer_flag}" -fno-omit-frame-pointer)
    target_link_options(heyaki_sqlite PUBLIC
      "${sqlite_sanitizer_flag}" -fno-omit-frame-pointer)
  endif()
endfunction()

# M11-02 (A1): vendored OpenSSL for Android. Android ships no system OpenSSL
# and Heyaki freezes the OpenSSL 3.x ABI line (M3A), so the TLS backend is
# built from the pinned third_party/openssl checkout with OpenSSL's own
# Configure (out-of-tree, against the NDK toolchain) and installed into a
# standard stage layout inside the build tree. The stage is exposed through
# OPENSSL_ROOT_DIR plus CMAKE_FIND_ROOT_PATH so the regular find_package
# (OpenSSL) flow — this project's, with its 3.x floor/4.x freeze gates, and
# the pinned libdatachannel's — resolves the vendored artifacts unchanged.
# Desktop builds keep the system OpenSSL path and never call this function.
function(heyaki_add_vendored_openssl)
  if(TARGET OpenSSL::SSL OR TARGET OpenSSL::Crypto)
    return()
  endif()

  set(openssl_root "${CMAKE_CURRENT_SOURCE_DIR}/third_party/openssl")
  if(NOT EXISTS "${openssl_root}/Configure")
    message(FATAL_ERROR
      "Pinned OpenSSL checkout is missing. Run `scripts/fetch_third_party.sh openssl`.")
  endif()

  # OpenSSL's Configure carries first-class android targets; map the NDK ABI
  # onto them instead of maintaining a custom toolchain.
  if(ANDROID_ABI STREQUAL "arm64-v8a")
    set(openssl_target android-arm64)
  elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
    set(openssl_target android-arm)
  elseif(ANDROID_ABI STREQUAL "x86_64")
    set(openssl_target android-x86_64)
  elseif(ANDROID_ABI STREQUAL "x86")
    set(openssl_target android-x86)
  else()
    message(FATAL_ERROR
      "No pinned OpenSSL android target for ANDROID_ABI='${ANDROID_ABI}'")
  endif()

  # Heyaki's POSIX interface enumeration uses getifaddrs/if_nametoindex,
  # which bionic provides from API 24; the Android build floor is therefore
  # android-24 (scripts/build_android.sh passes it explicitly).
  string(REGEX MATCH "[0-9]+$" openssl_api_level "${ANDROID_PLATFORM}")
  if(NOT openssl_api_level)
    set(openssl_api_level 24)
  endif()
  if(openssl_api_level LESS 24)
    message(FATAL_ERROR
      "Heyaki Android requires ANDROID_PLATFORM >= android-24 (bionic "
      "getifaddrs), got '${ANDROID_PLATFORM}'")
  endif()
  if(NOT ANDROID_NDK)
    message(FATAL_ERROR
      "ANDROID_NDK is not set; configure through the NDK toolchain file "
      "(scripts/build_android.sh)")
  endif()

  set(openssl_build_dir "${CMAKE_BINARY_DIR}/vendored/openssl")
  set(openssl_stage_dir "${CMAKE_BINARY_DIR}/vendored/openssl-stage")
  set(openssl_stage_libs
    "${openssl_stage_dir}/lib/libssl.a"
    "${openssl_stage_dir}/lib/libcrypto.a")

  if(NOT EXISTS "${openssl_stage_dir}/lib/libssl.a" OR
     NOT EXISTS "${openssl_stage_dir}/lib/libcrypto.a")
    find_program(HEYAKI_PERL_EXECUTABLE NAMES perl REQUIRED)
    find_program(HEYAKI_VENDORED_MAKE_EXECUTABLE NAMES gmake make REQUIRED)
    file(MAKE_DIRECTORY "${openssl_build_dir}")
    cmake_host_system_information(RESULT openssl_jobs
      QUERY NUMBER_OF_LOGICAL_CORES)

    message(STATUS
      "Configuring vendored OpenSSL for ${openssl_target} (API ${openssl_api_level})")
    # OpenSSL's android targets pick their compiler by finding the NDK clang
    # on PATH (which() must resolve inside the NDK prebuilt tree), then select
    # the API-specific wrapper (e.g. aarch64-linux-android24-clang).
    file(GLOB openssl_ndk_bin_dirs
      "${ANDROID_NDK}/toolchains/llvm/prebuilt/*/bin")
    if(NOT openssl_ndk_bin_dirs)
      message(FATAL_ERROR
        "No LLVM toolchain bin directory under "
        "${ANDROID_NDK}/toolchains/llvm/prebuilt; NDK layout not recognized")
    endif()
    list(GET openssl_ndk_bin_dirs 0 openssl_ndk_bin_dir)
    set(ENV{ANDROID_NDK_ROOT} "${ANDROID_NDK}")
    set(ENV{PATH} "${openssl_ndk_bin_dir}:$ENV{PATH}")
    execute_process(
      COMMAND "${HEYAKI_PERL_EXECUTABLE}" "${openssl_root}/Configure"
        "${openssl_target}"
        "-D__ANDROID_API__=${openssl_api_level}"
        "--prefix=${openssl_stage_dir}"
        "--openssldir=${openssl_stage_dir}/ssl"
        no-shared no-tests no-docs
      WORKING_DIRECTORY "${openssl_build_dir}"
      RESULT_VARIABLE openssl_configure_result
      OUTPUT_VARIABLE openssl_configure_output
      ERROR_VARIABLE openssl_configure_error)
    if(NOT openssl_configure_result EQUAL 0)
      message(FATAL_ERROR
        "Pinned OpenSSL Configure failed: ${openssl_configure_result}\n"
        "${openssl_configure_output}${openssl_configure_error}")
    endif()

    message(STATUS "Building vendored OpenSSL (${openssl_jobs} jobs)")
    execute_process(
      COMMAND "${HEYAKI_VENDORED_MAKE_EXECUTABLE}" "-j${openssl_jobs}" build_libs
      WORKING_DIRECTORY "${openssl_build_dir}"
      RESULT_VARIABLE openssl_build_result
      OUTPUT_VARIABLE openssl_build_output
      ERROR_VARIABLE openssl_build_error)
    if(NOT openssl_build_result EQUAL 0)
      message(FATAL_ERROR
        "Pinned OpenSSL build failed: ${openssl_build_result}\n"
        "${openssl_build_output}${openssl_build_error}")
    endif()

    execute_process(
      COMMAND "${HEYAKI_VENDORED_MAKE_EXECUTABLE}" install_sw
      WORKING_DIRECTORY "${openssl_build_dir}"
      RESULT_VARIABLE openssl_install_result
      OUTPUT_VARIABLE openssl_install_output
      ERROR_VARIABLE openssl_install_error)
    if(NOT openssl_install_result EQUAL 0)
      message(FATAL_ERROR
        "Pinned OpenSSL install_sw failed: ${openssl_install_result}\n"
        "${openssl_install_output}${openssl_install_error}")
    endif()
  endif()

  foreach(openssl_stage_lib IN LISTS openssl_stage_libs)
    if(NOT EXISTS "${openssl_stage_lib}")
      message(FATAL_ERROR
        "Vendored OpenSSL stage is incomplete: missing ${openssl_stage_lib}")
    endif()
  endforeach()

  # The NDK toolchain re-roots find_* searches (ONLY modes), so the stage
  # must join CMAKE_FIND_ROOT_PATH for find_package(OpenSSL) to see it.
  list(APPEND CMAKE_FIND_ROOT_PATH "${openssl_stage_dir}")
  set(CMAKE_FIND_ROOT_PATH "${CMAKE_FIND_ROOT_PATH}" PARENT_SCOPE)
  # Exposed to the top-level install rules: the vendored archives are part of
  # the Android artifact set (heyaki_client/libdatachannel link them privately,
  # and the final application link needs them in the install tree).
  set(HEYAKI_VENDORED_OPENSSL_STAGE "${openssl_stage_dir}" PARENT_SCOPE)
  set(OPENSSL_ROOT_DIR "${openssl_stage_dir}" CACHE PATH
    "Vendored OpenSSL stage for Android builds (M11-02)" FORCE)
  message(STATUS
    "Heyaki vendored OpenSSL: pinned third_party/openssl staged at ${openssl_stage_dir}")
endfunction()
