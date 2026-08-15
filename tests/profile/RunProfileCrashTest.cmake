if(NOT DEFINED HEYAKI_PROFILE_CRASH_PROBE OR
   NOT DEFINED HEYAKI_PROFILE_CRASH_STATE_DIR)
  message(FATAL_ERROR "Profile crash probe and state directory are required")
endif()

file(REMOVE_RECURSE "${HEYAKI_PROFILE_CRASH_STATE_DIR}")
file(MAKE_DIRECTORY "${HEYAKI_PROFILE_CRASH_STATE_DIR}")

function(run_probe result_variable)
  execute_process(
    COMMAND "${HEYAKI_PROFILE_CRASH_PROBE}" ${ARGN}
    RESULT_VARIABLE probe_result
    OUTPUT_VARIABLE probe_stdout
    ERROR_VARIABLE probe_stderr)
  set(${result_variable} "${probe_result}" PARENT_SCOPE)
  set(${result_variable}_STDOUT "${probe_stdout}" PARENT_SCOPE)
  set(${result_variable}_STDERR "${probe_stderr}" PARENT_SCOPE)
endfunction()

function(run_crash_case category point prepare_mode crash_mode verify_mode)
  string(REPLACE "." "-" case_name "${point}")
  set(profile_path
    "${HEYAKI_PROFILE_CRASH_STATE_DIR}/${category}-${case_name}/profile.sqlite")

  if(NOT prepare_mode STREQUAL "none")
    run_probe(prepare_result "${prepare_mode}" "${profile_path}")
    if(NOT prepare_result EQUAL 0)
      message(FATAL_ERROR
        "Profile crash preparation failed for ${point}: ${prepare_result}\n"
        "stdout:\n${prepare_result_STDOUT}\n"
        "stderr:\n${prepare_result_STDERR}")
    endif()
  endif()

  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env
      "HEYAKI_PROFILE_FAULT_POINT=${point}"
      "${HEYAKI_PROFILE_CRASH_PROBE}" "${crash_mode}" "${profile_path}"
    RESULT_VARIABLE crash_result
    OUTPUT_VARIABLE crash_stdout
    ERROR_VARIABLE crash_stderr)
  if(NOT crash_result EQUAL 86)
    message(FATAL_ERROR
      "Profile crash point ${point} returned ${crash_result}, expected 86\n"
      "stdout:\n${crash_stdout}\n"
      "stderr:\n${crash_stderr}")
  endif()

  run_probe(verify_result "${verify_mode}" "${profile_path}")
  if(NOT verify_result EQUAL 0)
    message(FATAL_ERROR
      "Profile recovery verification failed for ${point}: ${verify_result}\n"
      "stdout:\n${verify_result_STDOUT}\n"
      "stderr:\n${verify_result_STDERR}")
  endif()
endfunction()

foreach(point IN ITEMS
    schema.after_begin
    schema.after_apply
    schema.after_commit)
  run_crash_case(schema "${point}" none create verify-create)
endforeach()

foreach(point IN ITEMS
    migration.after_begin
    migration.after_apply
    migration.after_commit)
  run_crash_case(migration "${point}" prepare-migration migrate verify-migration)
endforeach()

foreach(point IN ITEMS
    trust_grant.after_begin
    trust_grant.after_grant
    trust_grant.after_scope_delete
    trust_grant.after_scope_1
    trust_grant.after_scope_2
    trust_grant.after_scope_3
    trust_grant.before_commit
    trust_grant.after_commit)
  run_crash_case(trust-grant "${point}" prepare-grant grant verify-grant)
endforeach()
