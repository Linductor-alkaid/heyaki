include_guard(GLOBAL)

set(_heyaki_valid_sanitizers none address undefined thread)
if(NOT HEYAKI_SANITIZER IN_LIST _heyaki_valid_sanitizers)
  message(FATAL_ERROR
    "Invalid HEYAKI_SANITIZER='${HEYAKI_SANITIZER}'. Expected one of: "
    "${_heyaki_valid_sanitizers}")
endif()

if(HEYAKI_ENABLE_CLANG_TIDY)
  find_program(HEYAKI_CLANG_TIDY_EXECUTABLE NAMES clang-tidy REQUIRED)
endif()
if(HEYAKI_ENABLE_IWYU)
  find_program(HEYAKI_IWYU_EXECUTABLE NAMES include-what-you-use iwyu REQUIRED)
endif()

function(heyaki_configure_target target_name)
  if(MSVC)
    target_compile_options(${target_name} PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8)
    if(HEYAKI_WARNINGS_AS_ERRORS)
      target_compile_options(${target_name} PRIVATE /WX)
    endif()
    if(NOT HEYAKI_ENABLE_EXCEPTIONS)
      target_compile_options(${target_name} PRIVATE /EHs-c-)
      target_compile_definitions(${target_name} PRIVATE _HAS_EXCEPTIONS=0)
    endif()
  elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    target_compile_options(${target_name} PRIVATE
      -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
    if(HEYAKI_WARNINGS_AS_ERRORS)
      target_compile_options(${target_name} PRIVATE -Werror)
    endif()
    if(NOT HEYAKI_ENABLE_EXCEPTIONS)
      target_compile_options(${target_name} PRIVATE -fno-exceptions)
    endif()
  endif()

  if(NOT HEYAKI_SANITIZER STREQUAL "none")
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
      message(FATAL_ERROR
        "HEYAKI_SANITIZER=${HEYAKI_SANITIZER} requires GCC or Clang in the M0 baseline")
    endif()
    if(HEYAKI_SANITIZER STREQUAL "address")
      set(sanitizer_flag -fsanitize=address)
    elseif(HEYAKI_SANITIZER STREQUAL "undefined")
      set(sanitizer_flag -fsanitize=undefined)
    elseif(HEYAKI_SANITIZER STREQUAL "thread")
      set(sanitizer_flag -fsanitize=thread)
    endif()
    target_compile_options(${target_name} PRIVATE "${sanitizer_flag}" -fno-omit-frame-pointer)
    get_target_property(target_type ${target_name} TYPE)
    if(target_type MATCHES "^(STATIC|SHARED|MODULE)_LIBRARY$")
      # An installed instrumented static library still requires the matching
      # sanitizer runtime in its final consumer link.
      target_link_options(${target_name} PUBLIC "${sanitizer_flag}" -fno-omit-frame-pointer)
    else()
      target_link_options(${target_name} PRIVATE "${sanitizer_flag}" -fno-omit-frame-pointer)
    endif()
  endif()

  if(HEYAKI_ENABLE_CLANG_TIDY)
    set_property(TARGET ${target_name} PROPERTY CXX_CLANG_TIDY
      "${HEYAKI_CLANG_TIDY_EXECUTABLE};--warnings-as-errors=*")
  endif()
  if(HEYAKI_ENABLE_IWYU)
    set_property(TARGET ${target_name} PROPERTY CXX_INCLUDE_WHAT_YOU_USE
      "${HEYAKI_IWYU_EXECUTABLE}")
  endif()
endfunction()

function(heyaki_add_developer_targets)
  file(GLOB_RECURSE heyaki_format_files CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/apps/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp")
  find_program(HEYAKI_CLANG_FORMAT_EXECUTABLE NAMES clang-format)
  if(HEYAKI_CLANG_FORMAT_EXECUTABLE)
    add_custom_target(heyaki-format
      COMMAND "${HEYAKI_CLANG_FORMAT_EXECUTABLE}" -i ${heyaki_format_files}
      COMMAND_EXPAND_LISTS
      VERBATIM)
    add_custom_target(heyaki-format-check
      COMMAND "${HEYAKI_CLANG_FORMAT_EXECUTABLE}" --dry-run --Werror ${heyaki_format_files}
      COMMAND_EXPAND_LISTS
      VERBATIM)
  else()
    add_custom_target(heyaki-format
      COMMAND "${CMAKE_COMMAND}" -E echo
        "clang-format is unavailable; install it to use the heyaki-format target"
      COMMAND "${CMAKE_COMMAND}" -E false
      VERBATIM)
    add_custom_target(heyaki-format-check
      COMMAND "${CMAKE_COMMAND}" -E echo
        "clang-format is unavailable; install it to use the heyaki-format-check target"
      COMMAND "${CMAKE_COMMAND}" -E false
      VERBATIM)
  endif()
endfunction()
