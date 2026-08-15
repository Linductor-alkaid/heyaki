include("${HEYAKI_VENDORED_RUNTIME_MODULE}")

function(assert_vcvars_arch platform expected_arch)
  heyaki_visual_studio_platform_to_vcvars_arch(actual_arch "${platform}")
  if(NOT actual_arch STREQUAL expected_arch)
    message(FATAL_ERROR
      "Visual Studio platform ${platform} mapped to ${actual_arch}; expected ${expected_arch}")
  endif()
endfunction()

assert_vcvars_arch(Win32 x86)
assert_vcvars_arch(x64 x64)
assert_vcvars_arch(ARM arm)
assert_vcvars_arch(ARM64 arm64)

heyaki_visual_studio_platform_to_vcvars_arch(
  versioned_arch "x64,version=10.0.26100.0")
if(NOT versioned_arch STREQUAL "x64")
  message(FATAL_ERROR
    "Versioned Visual Studio platform mapped to ${versioned_arch}; expected x64")
endif()

set(test_root "${HEYAKI_TEST_WORK_DIR}/Visual Studio SQLite Generation")
set(visual_studio_root "${test_root}/Visual Studio 2022")
set(sqlite_source_dir "${test_root}/SQLite Source's")
set(generation_script "${test_root}/SQLite Build/generate-amalgamation.ps1")
file(MAKE_DIRECTORY "${test_root}/SQLite Build")

heyaki_write_sqlite_msvc_generation_script(
  "${generation_script}" "${visual_studio_root}" x64 "${sqlite_source_dir}")
file(READ "${generation_script}" script_contents)

set(visual_studio_root_native "${visual_studio_root}")
set(sqlite_source_dir_native "${sqlite_source_dir}")
set(sqlite_makefile_native "${sqlite_source_dir}/Makefile.msc")
cmake_path(NATIVE_PATH visual_studio_root_native NORMALIZE visual_studio_root_native)
cmake_path(NATIVE_PATH sqlite_source_dir_native NORMALIZE sqlite_source_dir_native)
cmake_path(NATIVE_PATH sqlite_makefile_native NORMALIZE sqlite_makefile_native)
foreach(path_variable IN ITEMS
    visual_studio_root_native sqlite_source_dir_native sqlite_makefile_native)
  string(REPLACE "'" "''" ${path_variable} "${${path_variable}}")
endforeach()
foreach(expected_command IN ITEMS
    "$vsInstallPath = '${visual_studio_root_native}'"
    "$devShellModule = Join-Path $vsInstallPath 'Common7\\Tools\\Microsoft.VisualStudio.DevShell.dll'"
    "Write-Host '[heyaki-sqlite] initializing MSVC environment'"
    "Import-Module $devShellModule"
    "Enter-VsDevShell -VsInstallPath $vsInstallPath -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'"
    "Write-Host '[heyaki-sqlite] generating SQLite amalgamation'"
    "& nmake.exe /NOLOGO /f '${sqlite_makefile_native}' 'TOP=${sqlite_source_dir_native}' sqlite3.c sqlite3.h")
  string(FIND "${script_contents}" "${expected_command}" command_index)
  if(command_index EQUAL -1)
    message(FATAL_ERROR
      "Generated SQLite batch script is missing command:\n${expected_command}\n"
      "Generated script:\n${script_contents}")
  endif()
endforeach()
