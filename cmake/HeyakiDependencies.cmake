set(heyaki_bash_hints)
if(CMAKE_HOST_WIN32)
  list(APPEND heyaki_bash_hints
    "$ENV{ProgramFiles}/Git/bin"
    "$ENV{ProgramW6432}/Git/bin")
endif()
find_program(HEYAKI_BASH_EXECUTABLE
  NAMES bash bash.exe
  HINTS ${heyaki_bash_hints}
  DOC "Bash executable used by Heyaki dependency and test scripts")
mark_as_advanced(HEYAKI_BASH_EXECUTABLE)

if((HEYAKI_VERIFY_DEPENDENCIES OR BUILD_TESTING) AND NOT HEYAKI_BASH_EXECUTABLE)
  message(FATAL_ERROR
    "Bash is required for dependency verification and tests. "
    "Install Git for Windows or set HEYAKI_BASH_EXECUTABLE explicitly.")
endif()

function(heyaki_verify_dependencies)
  set(arguments --check)
  set(fetch_hint "scripts/fetch_third_party.sh")

  if(BUILD_TESTING)
    list(APPEND arguments --with-tests)
    string(APPEND fetch_hint " --with-tests")
  endif()
  if(HEYAKI_VERIFY_ZSTD_DEPENDENCY)
    list(APPEND arguments --with-optional)
    string(APPEND fetch_hint " --with-optional")
  endif()

  execute_process(
    COMMAND "${HEYAKI_BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/fetch_third_party.sh" ${arguments}
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    RESULT_VARIABLE dependency_result
    OUTPUT_VARIABLE dependency_output
    ERROR_VARIABLE dependency_error)
  if(NOT dependency_result EQUAL 0)
    message(FATAL_ERROR
      "Pinned dependency verification failed. Run `${fetch_hint}` and configure again.\n"
      "Process result: ${dependency_result}\n"
      "${dependency_output}${dependency_error}")
  endif()
  message(STATUS "Pinned dependency verification passed")
endfunction()
