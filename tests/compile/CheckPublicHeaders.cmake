if(NOT DEFINED HEYAKI_PUBLIC_INCLUDE_DIR)
  message(FATAL_ERROR "HEYAKI_PUBLIC_INCLUDE_DIR is required")
endif()

file(GLOB_RECURSE public_headers
  "${HEYAKI_PUBLIC_INCLUDE_DIR}/*.h"
  "${HEYAKI_PUBLIC_INCLUDE_DIR}/*.hpp")
if(NOT public_headers)
  message(FATAL_ERROR "No Heyaki public headers were found")
endif()

foreach(header IN LISTS public_headers)
  file(READ "${header}" contents)
  if(contents MATCHES "#include[ \t]*[<\"](rtc|ftxui)/" OR
     contents MATCHES "(^|[^A-Za-z0-9_])(rtc|ftxui)::" OR
     contents MATCHES "namespace[ \t]+(rtc|ftxui)([ \t]*[{:]|[ \t]*$)")
    message(FATAL_ERROR
      "Public header ${header} leaks a libdatachannel or FTXUI dependency")
  endif()
endforeach()

