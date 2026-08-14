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
    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/scripts/fetch_third_party.sh" ${arguments}
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    RESULT_VARIABLE dependency_result
    OUTPUT_VARIABLE dependency_output
    ERROR_VARIABLE dependency_error)
  if(NOT dependency_result EQUAL 0)
    message(FATAL_ERROR
      "Pinned dependency verification failed. Run `${fetch_hint}` and configure again.\n"
      "${dependency_output}${dependency_error}")
  endif()
  message(STATUS "Pinned dependency verification passed")
endfunction()
