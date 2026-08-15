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
  set(boost_modules asio system config assert throw_exception)
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

function(heyaki_target_use_pinned_boost_asio target_name)
  target_include_directories(${target_name} SYSTEM PRIVATE ${HEYAKI_BOOST_ASIO_INCLUDE_DIRS})
  target_compile_definitions(${target_name} PRIVATE
    BOOST_ERROR_CODE_HEADER_ONLY
    BOOST_SYSTEM_NO_DEPRECATED
    BOOST_ASIO_DISABLE_BOOST_DATE_TIME)
  target_link_libraries(${target_name} PRIVATE Threads::Threads)
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
    "${sodium_root}/crypto_aead/aegis128l/aegis128l_soft.c"
    "${sodium_root}/crypto_aead/aegis256/aead_aegis256.c"
    "${sodium_root}/crypto_aead/aegis256/aegis256_soft.c"
    "${sodium_root}/crypto_aead/aes256gcm/aead_aes256gcm.c"
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
    "${sodium_root}/crypto_generichash/blake2b/ref/blake2b-compress-ref.c"
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
    "${sodium_root}/crypto_pwhash/argon2/argon2-core.c"
    "${sodium_root}/crypto_pwhash/argon2/argon2-encoding.c"
    "${sodium_root}/crypto_pwhash/argon2/argon2-fill-block-ref.c"
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
    "${sodium_root}/crypto_stream/chacha20/ref/chacha20_ref.c"
    "${sodium_root}/crypto_stream/chacha20/stream_chacha20.c"
    "${sodium_root}/crypto_stream/crypto_stream.c"
    "${sodium_root}/crypto_stream/salsa20/ref/salsa20_ref.c"
    "${sodium_root}/crypto_stream/salsa20/stream_salsa20.c"
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
  target_compile_definitions(heyaki_sodium PRIVATE SODIUM_STATIC CONFIGURED=1)
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
