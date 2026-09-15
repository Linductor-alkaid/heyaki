file(READ "${HEYAKI_SBOM_FILE}" sbom)
file(READ "${HEYAKI_LICENSE_MANIFEST_FILE}" license_manifest)

if(NOT DEFINED HEYAKI_PROJECT_VERSION OR NOT DEFINED HEYAKI_BUILD_COMMIT)
  message(FATAL_ERROR "HEYAKI_PROJECT_VERSION and HEYAKI_BUILD_COMMIT are required")
endif()

# M9-14: the release SBOM must describe the heyaki package itself, with the
# exact project version and build commit stamped into both the package
# version and the document namespace.
foreach(release_identity IN ITEMS
    "PackageName: heyaki(\n|$)"
    "SPDXID: SPDXRef-Package-heyaki\n"
    "PackageVersion: ${HEYAKI_PROJECT_VERSION}[+]${HEYAKI_BUILD_COMMIT}\n"
    "Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-heyaki\n"
    "DocumentNamespace: https://heyaki[.]invalid/sbom/${HEYAKI_PROJECT_VERSION}/${HEYAKI_BUILD_COMMIT}\n")
  if(NOT sbom MATCHES "${release_identity}")
    message(FATAL_ERROR "SBOM is missing release identity: ${release_identity}")
  endif()
endforeach()

foreach(package IN ITEMS
    FTXUI executor boost-asio boost-system boost-config boost-assert boost-throw_exception boost-predef boost-winapi
    boost-beast boost-bind boost-container_hash boost-core boost-describe boost-endian boost-intrusive boost-io boost-move boost-mp11 boost-optional boost-preprocessor boost-smart_ptr boost-static_assert boost-static_string boost-type_index boost-type_traits boost-utility
    libdatachannel libsodium protobuf abseil-cpp blake3 sqlite googletest zstd
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
