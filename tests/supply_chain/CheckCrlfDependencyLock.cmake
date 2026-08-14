file(READ "${HEYAKI_DEPENDENCY_LOCK}" lock_contents)
string(REPLACE "\r" "" lock_contents "${lock_contents}")

file(MAKE_DIRECTORY "${HEYAKI_TEST_WORK_DIR}")
foreach(carriage_returns IN ITEMS "\r" "\r\r")
  string(REPLACE "\n" "${carriage_returns}\n" test_lock_contents "${lock_contents}")
  string(LENGTH "${carriage_returns}" carriage_return_count)
  set(crlf_lock
    "${HEYAKI_TEST_WORK_DIR}/dependencies-${carriage_return_count}-cr.lock")
  file(WRITE "${crlf_lock}" "${test_lock_contents}")

  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env
      "HEYAKI_DEPENDENCIES_LOCK=${crlf_lock}"
      "${HEYAKI_BASH_EXECUTABLE}" "${HEYAKI_FETCH_SCRIPT}" --list
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error)

  if(NOT result EQUAL 0)
    message(FATAL_ERROR
      "Dependency lock parsing failed with ${carriage_return_count} CR:\n${output}${error}")
  endif()

  foreach(expected_dependency IN ITEMS executor libdatachannel googletest zstd)
    if(NOT output MATCHES "(^|\n)${expected_dependency} +")
      message(FATAL_ERROR
        "Dependency lock output is missing ${expected_dependency} with "
        "${carriage_return_count} CR:\n${output}")
    endif()
  endforeach()
endforeach()
