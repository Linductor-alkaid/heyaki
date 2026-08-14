foreach(required_variable
    HEYAKI_ROOT_BINARY_DIR HEYAKI_CONSUMER_SOURCE_DIR HEYAKI_CONSUMER_WORK_DIR)
  if(NOT DEFINED ${required_variable})
    message(FATAL_ERROR "${required_variable} is required")
  endif()
endforeach()

set(install_dir "${HEYAKI_CONSUMER_WORK_DIR}/install")
set(build_dir "${HEYAKI_CONSUMER_WORK_DIR}/build")
file(REMOVE_RECURSE "${HEYAKI_CONSUMER_WORK_DIR}")
file(MAKE_DIRECTORY "${HEYAKI_CONSUMER_WORK_DIR}")

set(config_arguments)
if(DEFINED HEYAKI_CONFIG AND NOT HEYAKI_CONFIG STREQUAL "")
  list(APPEND config_arguments --config "${HEYAKI_CONFIG}")
endif()

execute_process(
  COMMAND "${CMAKE_COMMAND}" --install "${HEYAKI_ROOT_BINARY_DIR}"
    --prefix "${install_dir}" ${config_arguments}
  RESULT_VARIABLE install_result)
if(NOT install_result EQUAL 0)
  message(FATAL_ERROR "Heyaki installation failed")
endif()

execute_process(
  COMMAND "${CMAKE_COMMAND}" -S "${HEYAKI_CONSUMER_SOURCE_DIR}" -B "${build_dir}"
    "-DCMAKE_PREFIX_PATH=${install_dir}"
  RESULT_VARIABLE configure_result)
if(NOT configure_result EQUAL 0)
  message(FATAL_ERROR "Installed consumer configure failed")
endif()

execute_process(
  COMMAND "${CMAKE_COMMAND}" --build "${build_dir}" ${config_arguments}
  RESULT_VARIABLE build_result)
if(NOT build_result EQUAL 0)
  message(FATAL_ERROR "Installed consumer build failed")
endif()

