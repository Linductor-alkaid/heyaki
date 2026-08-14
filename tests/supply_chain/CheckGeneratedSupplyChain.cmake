file(READ "${HEYAKI_SBOM_FILE}" sbom)
file(READ "${HEYAKI_LICENSE_MANIFEST_FILE}" license_manifest)

foreach(package IN ITEMS
    FTXUI executor libdatachannel libsodium protobuf abseil-cpp blake3 sqlite googletest zstd
    nlohmann-json libjuice libsrtp plog usrsctp)
  if(NOT sbom MATCHES "PackageName: ${package}(\n|$)")
    message(FATAL_ERROR "SBOM is missing package ${package}")
  endif()
  string(FIND "${license_manifest}" "| ${package} |" manifest_package_index)
  if(manifest_package_index EQUAL -1)
    message(FATAL_ERROR "License manifest is missing package ${package}")
  endif()
endforeach()

foreach(submodule IN ITEMS nlohmann-json libjuice libsrtp plog usrsctp)
  set(expected_relationship
    "Relationship: SPDXRef-Package-libdatachannel DEPENDS_ON SPDXRef-Package-${submodule}")
  if(NOT sbom MATCHES "${expected_relationship}")
    message(FATAL_ERROR "SBOM is missing relationship: ${expected_relationship}")
  endif()
endforeach()
