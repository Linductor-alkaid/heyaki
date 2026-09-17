# Runs every compiled doc example and validates every extracted relay
# config (M9-16). Invoked by the heyaki_m9_docs_examples CTest.
#
# Inputs (required):
#   HEYAKI_DOC_CPP_BINARIES  - list of example executable paths (already
#                              generator-expression resolved by CTest)
#   HEYAKI_DOC_RELAY_CONFIGS - list of extracted .conf paths
#   HEYAKI_DOC_CONFIG_CHECK  - relay config checker executable path
#   HEYAKI_DOC_WORK_DIR      - scratch directory (argv[1] per example)

foreach(required_variable HEYAKI_DOC_CPP_BINARIES HEYAKI_DOC_RELAY_CONFIGS
    HEYAKI_DOC_CONFIG_CHECK HEYAKI_DOC_WORK_DIR)
  if(NOT DEFINED ${required_variable})
    message(FATAL_ERROR "${required_variable} is required")
  endif()
endforeach()

file(REMOVE_RECURSE "${HEYAKI_DOC_WORK_DIR}")
file(MAKE_DIRECTORY "${HEYAKI_DOC_WORK_DIR}")

foreach(example_binary IN LISTS HEYAKI_DOC_CPP_BINARIES)
  get_filename_component(example_name "${example_binary}" NAME_WE)
  string(REGEX REPLACE "^heyaki-doc-example-" "" example_slug "${example_name}")
  set(work_dir "${HEYAKI_DOC_WORK_DIR}/${example_slug}")
  file(MAKE_DIRECTORY "${work_dir}")
  # ProfileStore rejects group/other-accessible directories in its chain.
  file(CHMOD "${work_dir}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
  execute_process(
    COMMAND "${example_binary}" "${work_dir}"
    RESULT_VARIABLE result)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "Doc example '${example_slug}' failed with exit ${result}")
  endif()
  message(STATUS "doc example ok: ${example_slug}")
endforeach()

foreach(config_path IN LISTS HEYAKI_DOC_RELAY_CONFIGS)
  get_filename_component(config_slug "${config_path}" NAME_WE)
  set(work_dir "${HEYAKI_DOC_WORK_DIR}/${config_slug}")
  file(MAKE_DIRECTORY "${work_dir}")
  file(CHMOD "${work_dir}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
  execute_process(
    COMMAND "${HEYAKI_DOC_CONFIG_CHECK}" "${config_path}" "${work_dir}"
    RESULT_VARIABLE result)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR
      "Relay config example '${config_slug}' failed with exit ${result}")
  endif()
  message(STATUS "relay-config example ok: ${config_slug}")
endforeach()

message(STATUS "All doc examples passed")
