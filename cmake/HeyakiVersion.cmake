function(heyaki_resolve_build_commit output_variable)
  if(HEYAKI_BUILD_COMMIT)
    set(resolved_commit "${HEYAKI_BUILD_COMMIT}")
  else()
    execute_process(
      COMMAND git rev-parse --verify HEAD
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
      RESULT_VARIABLE git_result
      OUTPUT_VARIABLE resolved_commit
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET)
    if(NOT git_result EQUAL 0)
      set(resolved_commit "unknown")
    endif()
  endif()
  set(${output_variable} "${resolved_commit}" PARENT_SCOPE)
endfunction()

function(heyaki_generate_supply_chain_files output_dir sbom_output manifest_output)
  set(sbom_file "${output_dir}/heyaki.spdx")
  set(manifest_file "${output_dir}/THIRD_PARTY_LICENSES.md")
  add_custom_command(
    OUTPUT "${sbom_file}" "${manifest_file}"
    COMMAND "${CMAKE_COMMAND}"
      "-DHEYAKI_DEPENDENCY_LOCK=${CMAKE_CURRENT_SOURCE_DIR}/third_party/dependencies.lock"
      "-DHEYAKI_TRANSITIVE_DEPENDENCY_LOCK=${CMAKE_CURRENT_SOURCE_DIR}/third_party/transitive-dependencies.lock"
      "-DHEYAKI_LICENSE_LOCK=${CMAKE_CURRENT_SOURCE_DIR}/third_party/licenses.lock"
      "-DHEYAKI_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
      "-DHEYAKI_OUTPUT_DIR=${output_dir}"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/GenerateSupplyChain.cmake"
    DEPENDS
      "${CMAKE_CURRENT_SOURCE_DIR}/third_party/dependencies.lock"
      "${CMAKE_CURRENT_SOURCE_DIR}/third_party/transitive-dependencies.lock"
      "${CMAKE_CURRENT_SOURCE_DIR}/third_party/licenses.lock"
      "${CMAKE_CURRENT_SOURCE_DIR}/cmake/GenerateSupplyChain.cmake"
    VERBATIM)
  add_custom_target(heyaki-sbom ALL DEPENDS "${sbom_file}" "${manifest_file}")
  set(${sbom_output} "${sbom_file}" PARENT_SCOPE)
  set(${manifest_output} "${manifest_file}" PARENT_SCOPE)
endfunction()
