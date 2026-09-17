# M9-17: manifest-driven uninstall. `cmake --build <dir> --target uninstall`
# removes exactly the files CMake recorded in install_manifest.txt (any
# install into any prefix updates that manifest); directories are removed
# only when empty. The packaging test verifies the prefix is left without
# regular files, which is the uninstall contract for a non-package-manager
# install.
if(NOT DEFINED HEYAKI_INSTALL_MANIFEST)
  message(FATAL_ERROR "HEYAKI_INSTALL_MANIFEST (path to install_manifest.txt) is required")
endif()
if(NOT EXISTS "${HEYAKI_INSTALL_MANIFEST}")
  message(FATAL_ERROR
    "Cannot find install manifest ${HEYAKI_INSTALL_MANIFEST}. "
    "Run an install first.")
endif()

file(READ "${HEYAKI_INSTALL_MANIFEST}" uninstall_files)
string(REPLACE "\n" ";" uninstall_files "${uninstall_files}")
foreach(uninstall_file IN LISTS uninstall_files)
  if(uninstall_file STREQUAL "")
    continue()
  endif()
  if(IS_SYMLINK "${uninstall_file}" OR EXISTS "${uninstall_file}")
    file(REMOVE "${uninstall_file}")
    message(STATUS "Removed: ${uninstall_file}")
  else()
    message(STATUS "Missing on uninstall: ${uninstall_file}")
  endif()
endforeach()

# Remove directories bottom-up, but only those CMake created inside the
# prefix (they are empty once their files are gone).
list(SORT uninstall_files)
list(REVERSE uninstall_files)
foreach(uninstall_file IN LISTS uninstall_files)
  if(uninstall_file STREQUAL "")
    continue()
  endif()
  get_filename_component(uninstall_dir "${uninstall_file}" DIRECTORY)
  if(IS_DIRECTORY "${uninstall_dir}")
    file(GLOB uninstall_dir_entries LIST_DIRECTORIES true
      "${uninstall_dir}/*")
    if(NOT uninstall_dir_entries)
      # Only reached when the directory is empty, so recursive removal is a
      # no-op beyond the directory itself.
      file(REMOVE_RECURSE "${uninstall_dir}")
    endif()
  endif()
endforeach()
