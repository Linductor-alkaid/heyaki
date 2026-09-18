if(NOT DEFINED HEYAKI_DEPENDENCY_LOCK OR
   NOT DEFINED HEYAKI_TRANSITIVE_DEPENDENCY_LOCK OR
   NOT DEFINED HEYAKI_LICENSE_LOCK OR
   NOT DEFINED HEYAKI_SOURCE_DIR OR
   NOT DEFINED HEYAKI_OUTPUT_DIR OR
   NOT DEFINED HEYAKI_PROJECT_VERSION OR
   NOT DEFINED HEYAKI_BUILD_COMMIT)
  message(FATAL_ERROR
    "Direct/transitive dependency locks, license lock, source directory, output directory, "
    "project version, and build commit are required")
endif()

# M9-14 license policy gate. Every atom of an SPDX expression must be
# permissive for dependencies that end up linked into shipped artifacts
# (runtime, test, and the recursive libdatachannel submodules, which inherit
# runtime policy). Copyleft atoms are only tolerated in the optional group
# when the expression is a disjunction, because the build then selects the
# permissive branch (zstd: BSD-3-Clause OR GPL-2.0-only, not built in v1).
function(heyaki_enforce_license_policy dependency_name license_expression group)
  string(REPLACE "(" " " policy_tokens "${license_expression}")
  string(REPLACE ")" " " policy_tokens "${policy_tokens}")
  string(REPLACE " AND " ";" policy_tokens "${policy_tokens}")
  string(REPLACE " OR " ";" policy_tokens "${policy_tokens}")
  set(policy_copyleft_atoms)
  foreach(token IN LISTS policy_tokens)
    string(STRIP "${token}" token)
    if(token STREQUAL "" OR token STREQUAL "WITH")
      continue()
    endif()
    if(token MATCHES "^(AGPL|GPL|LGPL|SSPL)-")
      list(APPEND policy_copyleft_atoms "${token}")
    endif()
  endforeach()
  if(NOT policy_copyleft_atoms)
    return()
  endif()
  if(group STREQUAL "optional" AND license_expression MATCHES " OR ")
    message(STATUS
      "License policy: ${dependency_name} (${group}) keeps copyleft alternatives "
      "[${policy_copyleft_atoms}] behind a permissive OR branch: ${license_expression}")
    return()
  endif()
  message(FATAL_ERROR
    "License policy violation: ${dependency_name} (group ${group}) declares copyleft "
    "atoms [${policy_copyleft_atoms}] in '${license_expression}'. Linked Heyaki "
    "dependencies must stay permissive; see docs/supply-chain/dependency-policy.md.")
endfunction()

file(STRINGS "${HEYAKI_LICENSE_LOCK}" license_lines)
set(license_names)
foreach(line IN LISTS license_lines)
  if(line STREQUAL "" OR line MATCHES "^#")
    continue()
  endif()
  string(REPLACE "|" ";" fields "${line}")
  list(LENGTH fields field_count)
  if(NOT field_count EQUAL 3)
    message(FATAL_ERROR "Invalid license lock entry: ${line}")
  endif()
  list(GET fields 0 dependency_name)
  list(GET fields 1 license_expression)
  list(GET fields 2 license_path)
  list(FIND license_names "${dependency_name}" license_index)
  if(NOT license_index EQUAL -1)
    message(FATAL_ERROR "Duplicate license metadata for ${dependency_name}")
  endif()
  if(NOT EXISTS "${HEYAKI_SOURCE_DIR}/${license_path}")
    message(FATAL_ERROR "License file for ${dependency_name} does not exist: ${license_path}")
  endif()
  list(APPEND license_names "${dependency_name}")
  set("license_${dependency_name}" "${license_expression}")
  set("license_path_${dependency_name}" "${license_path}")
endforeach()

file(MAKE_DIRECTORY "${HEYAKI_OUTPUT_DIR}")
set(sbom "SPDXVersion: SPDX-2.3\n")
string(APPEND sbom "DataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT\n")
string(APPEND sbom "DocumentName: heyaki-third-party\n")
string(APPEND sbom
  "DocumentNamespace: https://heyaki.invalid/sbom/${HEYAKI_PROJECT_VERSION}/${HEYAKI_BUILD_COMMIT}\n")
string(APPEND sbom "Creator: Tool: heyaki-cmake-m9\nCreated: 2026-08-14T00:00:00Z\n\n")
# The heyaki package itself: release SBOM consumers need one DESCRIBES entry
# for the shipped project, not only its dependencies. Heyaki is MIT (LICENSE
# at the repository root, v1.0.0 decision); the license policy below governs
# the third-party closure. Created stays pinned so the document is
# reproducible from the same tree; version and build commit in the namespace
# identify the release it describes.
string(APPEND sbom "PackageName: heyaki\n")
string(APPEND sbom "SPDXID: SPDXRef-Package-heyaki\n")
string(APPEND sbom "PackageVersion: ${HEYAKI_PROJECT_VERSION}+${HEYAKI_BUILD_COMMIT}\n")
string(APPEND sbom "PackageDownloadLocation: https://github.com/Linductor-alkaid/heyaki\n")
string(APPEND sbom "FilesAnalyzed: false\n")
string(APPEND sbom "PackageLicenseConcluded: MIT\n")
string(APPEND sbom "PackageLicenseDeclared: MIT\n")
string(APPEND sbom "Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-heyaki\n\n")
set(manifest "# Heyaki Third-Party Licenses\n\n")
string(APPEND manifest "Generated from `third_party/dependencies.lock` and `third_party/licenses.lock`.\n\n")
string(APPEND manifest
  "Transitive submodules are pinned by `third_party/transitive-dependencies.lock`.\n\n")
string(APPEND manifest "| Dependency | Scope | Version/ref | Commit | License | License file |\n")
string(APPEND manifest "| --- | --- | --- | --- | --- | --- |\n")

set(package_names)
macro(heyaki_append_package package_name package_version package_url package_commit
                           package_scope package_group)
  list(FIND package_names "${package_name}" package_index)
  if(NOT package_index EQUAL -1)
    message(FATAL_ERROR "Duplicate package metadata for ${package_name}")
  endif()
  if(NOT DEFINED "license_${package_name}")
    message(FATAL_ERROR "Missing license metadata for ${package_name}")
  endif()
  string(LENGTH "${package_commit}" package_commit_length)
  if(NOT package_commit_length EQUAL 40 OR
     NOT "${package_commit}" MATCHES "^[0-9a-f]+$")
    message(FATAL_ERROR "Invalid commit for ${package_name}: ${package_commit}")
  endif()

  set(license_expression "${license_${package_name}}")
  heyaki_enforce_license_policy("${package_name}" "${license_expression}" "${package_group}")
  set(license_path "${license_path_${package_name}}")
  list(APPEND package_names "${package_name}")

  string(APPEND sbom "PackageName: ${package_name}\n")
  string(APPEND sbom "SPDXID: SPDXRef-Package-${package_name}\n")
  string(APPEND sbom "PackageVersion: ${package_version}\n")
  string(APPEND sbom "PackageDownloadLocation: ${package_url}\n")
  string(APPEND sbom "PackageChecksum: SHA1: ${package_commit}\n")
  string(APPEND sbom "FilesAnalyzed: false\n")
  string(APPEND sbom "PackageLicenseConcluded: ${license_expression}\n")
  string(APPEND sbom "PackageLicenseDeclared: ${license_expression}\n")
  string(APPEND sbom
    "Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-${package_name}\n\n")
  string(APPEND manifest
  "| ${package_name} | ${package_scope} (${package_group}) | ${package_version} | `${package_commit}` | ${license_expression} | `${license_path}` |\n")
endmacro()

file(STRINGS "${HEYAKI_DEPENDENCY_LOCK}" dependency_lines)
set(direct_package_names)
foreach(line IN LISTS dependency_lines)
  if(line STREQUAL "" OR line MATCHES "^#")
    continue()
  endif()
  string(REPLACE "|" ";" fields "${line}")
  list(LENGTH fields field_count)
  if(NOT field_count EQUAL 6)
    message(FATAL_ERROR "Invalid dependency lock entry: ${line}")
  endif()
  list(GET fields 0 dependency_name)
  list(GET fields 1 dependency_url)
  list(GET fields 2 dependency_ref)
  list(GET fields 3 dependency_commit)
  list(GET fields 5 dependency_group)
  if(NOT dependency_group MATCHES "^(runtime|test|optional)$")
    message(FATAL_ERROR
      "Unknown dependency group '${dependency_group}' for ${dependency_name}")
  endif()
  list(APPEND direct_package_names "${dependency_name}")
  heyaki_append_package(
    "${dependency_name}" "${dependency_ref}" "${dependency_url}" "${dependency_commit}"
    "direct" "${dependency_group}")
endforeach()

list(LENGTH direct_package_names direct_package_count)
if(NOT direct_package_count EQUAL 35)
  message(FATAL_ERROR "Expected 35 direct pinned packages, found ${direct_package_count}")
endif()

file(STRINGS "${HEYAKI_TRANSITIVE_DEPENDENCY_LOCK}" transitive_lines)
set(transitive_package_count 0)
foreach(line IN LISTS transitive_lines)
  if(line STREQUAL "" OR line MATCHES "^#")
    continue()
  endif()
  string(REPLACE "|" ";" fields "${line}")
  list(LENGTH fields field_count)
  if(NOT field_count EQUAL 5)
    message(FATAL_ERROR "Invalid transitive dependency lock entry: ${line}")
  endif()
  list(GET fields 0 parent_name)
  list(GET fields 1 dependency_name)
  list(GET fields 3 dependency_url)
  list(GET fields 4 dependency_commit)
  list(FIND direct_package_names "${parent_name}" parent_index)
  if(parent_index EQUAL -1)
    message(FATAL_ERROR "Unknown direct parent ${parent_name} for ${dependency_name}")
  endif()
  # Recursive submodules are linked through libdatachannel into the shipped
  # artifacts, so the runtime license policy applies to them as well.
  heyaki_append_package(
    "${dependency_name}" "${dependency_commit}" "${dependency_url}" "${dependency_commit}"
    "submodule of `${parent_name}`" "runtime")
  string(APPEND sbom
    "Relationship: SPDXRef-Package-${parent_name} DEPENDS_ON SPDXRef-Package-${dependency_name}\n\n")
  math(EXPR transitive_package_count "${transitive_package_count} + 1")
endforeach()

if(NOT transitive_package_count EQUAL 5)
  message(FATAL_ERROR
    "Expected 5 transitive pinned packages, found ${transitive_package_count}")
endif()

list(LENGTH package_names package_count)
list(LENGTH license_names license_count)
if(NOT package_count EQUAL license_count)
  message(FATAL_ERROR
    "Expected one license record per package, found ${package_count} packages and ${license_count} licenses")
endif()

file(WRITE "${HEYAKI_OUTPUT_DIR}/heyaki.spdx" "${sbom}")
file(WRITE "${HEYAKI_OUTPUT_DIR}/THIRD_PARTY_LICENSES.md" "${manifest}")
