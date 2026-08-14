if(NOT DEFINED HEYAKI_TEST_PROGRAM)
  message(FATAL_ERROR "HEYAKI_TEST_PROGRAM is required")
endif()

execute_process(
  COMMAND "${HEYAKI_TEST_PROGRAM}" ${HEYAKI_TEST_ARGUMENTS}
  RESULT_VARIABLE test_result
  OUTPUT_VARIABLE test_output
  ERROR_VARIABLE test_error)
set(combined_output "${test_output}${test_error}")

if(test_result EQUAL 0)
  if(NOT combined_output STREQUAL "")
    message("${combined_output}")
  endif()
  return()
endif()

if(NOT HEYAKI_REQUIRE_SANITIZER_RUNTIME AND
   (combined_output MATCHES "LeakSanitizer does not work under ptrace" OR
    combined_output MATCHES "ThreadSanitizer: unexpected memory mapping"))
  message("HEYAKI_SANITIZER_UNSUPPORTED: ${combined_output}")
  return()
endif()

message(FATAL_ERROR
  "Sanitized test failed with exit ${test_result}:\n${combined_output}")
