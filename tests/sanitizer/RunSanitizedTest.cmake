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

# On affected Linux hosts, GCC ThreadSanitizer can terminate during runtime
# initialization with an empty SIGSEGV instead of its usual memory-mapping
# diagnostic. Retry only that no-output startup shape with TSAN verbosity so
# the known unsupported-host condition remains distinguishable from a test
# crash.
if(NOT HEYAKI_REQUIRE_SANITIZER_RUNTIME AND
   test_result STREQUAL "Segmentation fault" AND
   combined_output STREQUAL "")
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "TSAN_OPTIONS=verbosity=1"
      "${HEYAKI_TEST_PROGRAM}" ${HEYAKI_TEST_ARGUMENTS}
    RESULT_VARIABLE diagnostic_result
    OUTPUT_VARIABLE diagnostic_output
    ERROR_VARIABLE diagnostic_error)
  set(diagnostic_combined_output "${diagnostic_output}${diagnostic_error}")
  if(diagnostic_combined_output MATCHES "ThreadSanitizer: unexpected memory mapping")
    message("HEYAKI_SANITIZER_UNSUPPORTED: ${diagnostic_combined_output}")
    return()
  endif()
endif()

if(NOT HEYAKI_REQUIRE_SANITIZER_RUNTIME AND
   (combined_output MATCHES "LeakSanitizer does not work under ptrace" OR
    combined_output MATCHES "ThreadSanitizer: unexpected memory mapping"))
  message("HEYAKI_SANITIZER_UNSUPPORTED: ${combined_output}")
  return()
endif()

message(FATAL_ERROR
  "Sanitized test failed with exit ${test_result}:\n${combined_output}")
