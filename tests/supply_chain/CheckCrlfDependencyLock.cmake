file(READ "${HEYAKI_DEPENDENCY_LOCK}" lock_contents)
string(REPLACE "\r\n" "\n" lock_contents "${lock_contents}")
string(REPLACE "\n" "\r\n" lock_contents "${lock_contents}")

file(MAKE_DIRECTORY "${HEYAKI_TEST_WORK_DIR}")
set(crlf_lock "${HEYAKI_TEST_WORK_DIR}/dependencies-crlf.lock")
file(WRITE "${crlf_lock}" "${lock_contents}")

execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env
    "HEYAKI_DEPENDENCIES_LOCK=${crlf_lock}"
    "${HEYAKI_BASH_EXECUTABLE}" "${HEYAKI_FETCH_SCRIPT}" --list
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error)

if(NOT result EQUAL 0)
  message(FATAL_ERROR "CRLF dependency lock parsing failed:\n${output}${error}")
endif()

foreach(expected_dependency IN ITEMS executor libdatachannel googletest zstd)
  if(NOT output MATCHES "(^|\n)${expected_dependency} +")
    message(FATAL_ERROR
      "CRLF dependency lock output is missing ${expected_dependency}:\n${output}")
  endif()
endforeach()
