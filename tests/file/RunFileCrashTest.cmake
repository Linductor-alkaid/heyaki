if(NOT DEFINED HEYAKI_FILE_CRASH_PROBE OR
   NOT DEFINED HEYAKI_FILE_CRASH_STATE_DIR)
  message(FATAL_ERROR "File crash probe and state directory are required")
endif()

file(REMOVE_RECURSE "${HEYAKI_FILE_CRASH_STATE_DIR}")
file(MAKE_DIRECTORY "${HEYAKI_FILE_CRASH_STATE_DIR}")

# One crash case per on-disk boundary of the receive path. Each case runs in
# its own state directory: `push` must die exactly at the named point (exit
# 86 from the fault-injected file_store), then a fresh `verify` process must
# re-push the same content and see it commit byte-identical.
function(run_crash_case point)
  set(state_dir "${HEYAKI_FILE_CRASH_STATE_DIR}/${point}")
  file(MAKE_DIRECTORY "${state_dir}")

  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env
      "HEYAKI_FILE_FAULT_POINT=${point}"
      "${HEYAKI_FILE_CRASH_PROBE}" push "${state_dir}"
    RESULT_VARIABLE crash_result
    OUTPUT_VARIABLE crash_stdout
    ERROR_VARIABLE crash_stderr)
  if(NOT crash_result EQUAL 86)
    message(FATAL_ERROR
      "File crash point ${point} returned ${crash_result}, expected 86\n"
      "stdout:\n${crash_stdout}\n"
      "stderr:\n${crash_stderr}")
  endif()

  execute_process(
    COMMAND "${HEYAKI_FILE_CRASH_PROBE}" verify "${state_dir}" "${point}"
    RESULT_VARIABLE verify_result
    OUTPUT_VARIABLE verify_stdout
    ERROR_VARIABLE verify_stderr)
  if(NOT verify_result EQUAL 0)
    message(FATAL_ERROR
      "File crash recovery verification failed for ${point}: ${verify_result}\n"
      "stdout:\n${verify_stdout}\n"
      "stderr:\n${verify_stderr}")
  endif()
  message(STATUS "file crash case ${point}: crash + recovery OK")
endfunction()

foreach(point IN ITEMS
    staging.after_create
    chunk.after_write
    state.after_write
    commit.before_rename
    commit.after_rename
    commit.after_cleanup)
  run_crash_case("${point}")
endforeach()
