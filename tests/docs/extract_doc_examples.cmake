# Extracts sync-tested example blocks from documentation (M9-16).
#
# Fenced blocks tagged `heyaki-cpp <slug>` become standalone C++ programs;
# blocks tagged `heyaki-relay-config <slug>` become relay config files. Both
# are compiled/executed by the heyaki_m9_docs_examples test, so a sample that
# stops compiling or validating fails CI.
#
# Inputs (required):
#   HEYAKI_DOCS_LIST  - semicolon list of markdown files to scan
#   HEYAKI_OUTPUT_DIR - directory receiving <slug>.cpp / <slug>.conf
#                       plus the manifest (examples-manifest.cmake)
#
# The manifest sets:
#   HEYAKI_DOC_CPP_EXAMPLES  - list of slugs
#   HEYAKI_DOC_RELAY_CONFIGS - list of slugs
#
# Blocks are located by pairing ``` markers with string(FIND) over a moving
# remainder of the document (string(FIND) has no start-position parameter,
# and the text is never split into a CMake list because C/C++ block content
# itself contains semicolons).

foreach(required_variable HEYAKI_DOCS_LIST HEYAKI_OUTPUT_DIR)
  if(NOT DEFINED ${required_variable})
    message(FATAL_ERROR "${required_variable} is required")
  endif()
endforeach()

set(cpp_slugs "")
set(config_slugs "")

foreach(doc_file IN LISTS HEYAKI_DOCS_LIST)
  if(NOT EXISTS "${doc_file}")
    message(FATAL_ERROR "Doc example source missing: ${doc_file}")
  endif()
  file(READ "${doc_file}" doc_text)
  string(REPLACE "\r\n" "\n" doc_text "${doc_text}")
  string(LENGTH "${doc_text}" doc_length)

  set(offset 0)
  while(offset LESS doc_length)
    string(SUBSTRING "${doc_text}" "${offset}" -1 remainder)
    string(FIND "${remainder}" "```" fence_rel)
    if(fence_rel EQUAL -1)
      break()
    endif()
    math(EXPR info_start "${offset} + ${fence_rel} + 3")
    string(SUBSTRING "${doc_text}" "${info_start}" -1 after_info)
    string(FIND "${after_info}" "\n" info_newline)
    if(info_newline EQUAL -1)
      message(FATAL_ERROR "Unterminated fence info string in ${doc_file}")
    endif()
    string(SUBSTRING "${after_info}" 0 "${info_newline}" info_string)
    string(STRIP "${info_string}" info_string)
    math(EXPR content_start "${info_start} + ${info_newline} + 1")
    string(SUBSTRING "${doc_text}" "${content_start}" -1 after_content)
    string(FIND "${after_content}" "```" fence_close)
    if(fence_close EQUAL -1)
      message(FATAL_ERROR "Unbalanced code fence in ${doc_file}")
    endif()
    string(SUBSTRING "${after_content}" 0 "${fence_close}" block_content)
    math(EXPR offset "${content_start} + ${fence_close} + 3")

    if(info_string MATCHES "^heyaki-cpp +([a-z0-9][a-z0-9-]*)$")
      set(slug "${CMAKE_MATCH_1}")
      list(FIND cpp_slugs "${slug}" duplicate)
      if(NOT duplicate EQUAL -1)
        message(FATAL_ERROR "Duplicate heyaki-cpp example slug '${slug}'")
      endif()
      if(block_content STREQUAL "")
        message(FATAL_ERROR "heyaki-cpp example '${slug}' is empty")
      endif()
      file(WRITE "${HEYAKI_OUTPUT_DIR}/${slug}.cpp" "${block_content}")
      list(APPEND cpp_slugs "${slug}")
    elseif(info_string MATCHES "^heyaki-relay-config +([a-z0-9][a-z0-9-]*)$")
      set(slug "${CMAKE_MATCH_1}")
      list(FIND config_slugs "${slug}" duplicate)
      if(NOT duplicate EQUAL -1)
        message(FATAL_ERROR
          "Duplicate heyaki-relay-config example slug '${slug}'")
      endif()
      if(block_content STREQUAL "")
        message(FATAL_ERROR "heyaki-relay-config example '${slug}' is empty")
      endif()
      file(WRITE "${HEYAKI_OUTPUT_DIR}/${slug}.conf" "${block_content}")
      list(APPEND config_slugs "${slug}")
    endif()
  endwhile()
endforeach()

if(NOT cpp_slugs AND NOT config_slugs)
  message(FATAL_ERROR
    "No heyaki-cpp/heyaki-relay-config blocks found in the scanned docs - "
    "the extractor or the doc list is broken, not the docs")
endif()

list(SORT cpp_slugs)
list(SORT config_slugs)
file(WRITE "${HEYAKI_OUTPUT_DIR}/examples-manifest.cmake"
  "set(HEYAKI_DOC_CPP_EXAMPLES \"${cpp_slugs}\")\n"
  "set(HEYAKI_DOC_RELAY_CONFIGS \"${config_slugs}\")\n")
message(STATUS "Doc examples: cpp=[${cpp_slugs}] relay-config=[${config_slugs}]")
