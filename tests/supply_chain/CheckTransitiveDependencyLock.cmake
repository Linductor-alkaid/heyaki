file(STRINGS "${HEYAKI_TRANSITIVE_DEPENDENCY_LOCK}" lock_lines)
set(record_count 0)

foreach(line IN LISTS lock_lines)
  if(line STREQUAL "" OR line MATCHES "^#")
    continue()
  endif()
  string(REPLACE "|" ";" fields "${line}")
  list(LENGTH fields field_count)
  if(NOT field_count EQUAL 5)
    message(FATAL_ERROR "Invalid transitive dependency lock entry: ${line}")
  endif()
  list(GET fields 0 parent)
  list(GET fields 1 dependency)
  list(GET fields 2 relative_path)
  list(GET fields 3 expected_url)
  list(GET fields 4 expected_commit)
  set(checkout "${HEYAKI_SOURCE_DIR}/third_party/${parent}/${relative_path}")

  execute_process(
    COMMAND "${HEYAKI_GIT_EXECUTABLE}" -C "${checkout}" rev-parse HEAD
    RESULT_VARIABLE commit_result
    OUTPUT_VARIABLE actual_commit
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_VARIABLE commit_error)
  if(NOT commit_result EQUAL 0 OR NOT actual_commit STREQUAL expected_commit)
    message(FATAL_ERROR
      "${dependency} commit mismatch: expected ${expected_commit}, got ${actual_commit}\n${commit_error}")
  endif()

  execute_process(
    COMMAND "${HEYAKI_GIT_EXECUTABLE}" -C "${checkout}" remote get-url origin
    RESULT_VARIABLE url_result
    OUTPUT_VARIABLE actual_url
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_VARIABLE url_error)
  if(NOT url_result EQUAL 0 OR NOT actual_url STREQUAL expected_url)
    message(FATAL_ERROR
      "${dependency} URL mismatch: expected ${expected_url}, got ${actual_url}\n${url_error}")
  endif()

  math(EXPR record_count "${record_count} + 1")
endforeach()

execute_process(
  COMMAND "${HEYAKI_GIT_EXECUTABLE}" -C
    "${HEYAKI_SOURCE_DIR}/third_party/libdatachannel" submodule status --recursive
  RESULT_VARIABLE status_result
  OUTPUT_VARIABLE submodule_status
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_VARIABLE status_error)
if(NOT status_result EQUAL 0)
  message(FATAL_ERROR "Unable to inspect libdatachannel submodules:\n${status_error}")
endif()

string(REGEX MATCHALL "[^\n]+" submodule_lines "${submodule_status}")
list(LENGTH submodule_lines actual_submodule_count)
if(NOT actual_submodule_count EQUAL record_count)
  message(FATAL_ERROR
    "Transitive lock has ${record_count} records but checkout has ${actual_submodule_count} submodules")
endif()
