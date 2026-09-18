#!/usr/bin/env bash
# M9-17 release packaging.
#
# Produces from a configured+built Heyaki tree:
#   dist/heyaki-<version>-linux-<arch>.tar.gz      stripped install tree
#   dist/heyaki-<version>-linux-<arch>-dbg.tar.gz  split debug symbols
#   dist/SHA256SUMS
#
# The flow is the "clean machine" verification in one pass: install into a
# fresh prefix, assert the inventory (client libraries, relay, TUI, demos,
# coturn example configuration, license texts, SBOM), split debug symbols,
# verify the stripped binaries still run, create the tarballs, then simulate
# an uninstall (manifest-driven removal) and assert the prefix holds no
# regular files afterwards.
#
# Usage:
#   scripts/package_release.sh --build-dir <dir> --output <dir> [options]
#     --build-dir DIR  existing configured+built CMake binary directory
#                      (default: configure a fresh RelWithDebInfo build in
#                      <output>/build so the artifacts carry debug info)
#     --source-dir DIR source directory for a fresh configure (default: the
#                      repository containing this script)
#     --output DIR     working/output directory (default: ./heyaki-dist)
#     --skip-tarball   run install/inventory/symbols/uninstall verification
#                      only (CI smoke form; still requires debug info)
#
# Requires: cmake, tar, and binutils (objcopy/readelf); Linux only.
set -Eeuo pipefail

script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

build_dir=""
source_dir="${script_root}"
output_dir="${PWD}/heyaki-dist"
skip_tarball=0

while [ $# -gt 0 ]; do
  case "$1" in
    --build-dir)
      [ $# -ge 2 ] || { echo "package_release: missing value for $1" >&2; exit 2; }
      build_dir="$2"; shift 2 ;;
    --source-dir)
      [ $# -ge 2 ] || { echo "package_release: missing value for $1" >&2; exit 2; }
      source_dir="$2"; shift 2 ;;
    --output)
      [ $# -ge 2 ] || { echo "package_release: missing value for $1" >&2; exit 2; }
      output_dir="$2"; shift 2 ;;
    --skip-tarball) skip_tarball=1; shift ;;
    *)
      echo "package_release: unknown option: $1" >&2; exit 2 ;;
  esac
done

for tool in cmake tar readelf objcopy; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "package_release: required tool missing: $tool" >&2
    exit 1
  }
done

case "$(uname -s)" in
  Linux*) ;;
  *)
    echo "package_release: tarball packaging is Linux-only (got $(uname -s));" \
         "Windows install verification is covered by heyaki_installed_consumer" >&2
    exit 1
    ;;
esac

work="${output_dir}/package"
stage="${work}/stage"
dbg="${work}/dbg"
rm -rf "${work}"
mkdir -p "${stage}" "${dbg}" "${output_dir}/dist"

if [ -z "${build_dir}" ]; then
  build_dir="${work}/build"
  echo "== configuring fresh RelWithDebInfo build in ${build_dir}"
  cmake -S "${source_dir}" -B "${build_dir}" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DHEYAKI_WARNINGS_AS_ERRORS=OFF \
    -DBUILD_TESTING=OFF \
    -DHEYAKI_AUTO_INSTALL=OFF
  cmake --build "${build_dir}" --parallel "$(nproc)"
fi

[ -f "${build_dir}/CMakeCache.txt" ] || {
  echo "package_release: ${build_dir} is not a configured build directory" >&2
  exit 1
}

echo "== installing into clean prefix ${stage}"
cmake --install "${build_dir}" --prefix "${stage}"
manifest="${work}/install_manifest.txt"
[ -f "${build_dir}/install_manifest.txt" ] || {
  echo "package_release: install did not produce install_manifest.txt" >&2
  exit 1
}
cp "${build_dir}/install_manifest.txt" "${manifest}"

# ---------------------------------------------------------------------------
# Inventory: the M9-17 packaging contract.
# ---------------------------------------------------------------------------
expect_file() {
  [ -f "${stage}/$1" ] || { echo "package_release: missing from install: $1" >&2; exit 1; }
}

expect_file bin/heyaki-relay
expect_file bin/heyaki-tui
expect_file bin/heyaki-m2-profile-demo
expect_file bin/heyaki-m3b-relay-demo
expect_file bin/heyaki-m4-matrix-node
expect_file bin/heyaki-m7-data-demo
expect_file bin/heyaki-test-turn-server
expect_file bin/heyaki-release-sign
for header in node.hpp profile_store.hpp runtime.hpp metrics.hpp protocol.hpp; do
  expect_file "include/heyaki/${header}"
done
expect_file lib/cmake/heyaki/heyakiConfig.cmake
expect_file lib/cmake/heyaki/heyakiTargets.cmake
expect_file share/heyaki/proto/heyaki/session/v1/session.proto
expect_file share/heyaki/coturn/turnserver.conf
expect_file share/heyaki/coturn/docker-compose.yml
expect_file share/heyaki/coturn/heyaki-turn.env.example
expect_file share/heyaki/coturn/README.md
expect_file share/licenses/heyaki/LICENSE
expect_file share/heyaki/supply-chain/heyaki.spdx
expect_file share/heyaki/supply-chain/THIRD_PARTY_LICENSES.md
expect_file share/heyaki/licenses/libdatachannel-LICENSE
expect_file share/heyaki/licenses/executor-LICENSE
license_count="$(find "${stage}/share/heyaki/licenses" -type f | wc -l)"
[ "${license_count}" -ge 30 ] || {
  echo "package_release: expected >=30 license texts, found ${license_count}" >&2
  exit 1
}

version_line="$("${stage}/bin/heyaki-relay" --version)"
version="$(printf '%s\n' "${version_line}" | sed -n 's/^heyaki-relay \([^ ]*\) (.*)$/\1/p')"
[ -n "${version}" ] || {
  echo "package_release: cannot parse version from: ${version_line}" >&2
  exit 1
}
machine_arch="$(uname -m)"
package_root="heyaki-${version}-linux-${machine_arch}"
echo "== packaging ${package_root} (from: ${version_line})"

# ---------------------------------------------------------------------------
# Symbol split: debug sections into the dbg tree (mirroring paths), stripped
# copies stay in the stage tree. Exit 77 (CTest skip semantics) when the
# build carries no debug information at all (plain Release); the CI
# supply-chain job configures with -g so the split is exercised there.
# ---------------------------------------------------------------------------
symbol_candidates=0
symbol_file_count=0
while IFS= read -r -d '' elf; do
  if readelf -S "${elf}" 2>/dev/null | grep -q '\.debug_info'; then
    symbol_candidates=$((symbol_candidates + 1))
    relative="${elf#"${stage}/"}"
    debug_path="${dbg}/${relative}.debug"
    mkdir -p "$(dirname "${debug_path}")"
    objcopy --only-keep-debug "${elf}" "${debug_path}"
    objcopy --strip-debug "${elf}"
    symbol_file_count=$((symbol_file_count + 1))
  fi
done < <(find "${stage}/bin" "${stage}/lib" -type f -print0 2>/dev/null)

if [ "${symbol_candidates}" -eq 0 ]; then
  echo "PACKAGE_SKIP: build carries no debug information (configure with -g)"
  exit 77
fi
[ "${symbol_file_count}" -ge 5 ] || {
  echo "package_release: expected debug symbols in the packaged libraries and" \
       "binaries, found ${symbol_file_count}" >&2
  exit 1
}
echo "== split ${symbol_file_count} debug files"

# Stripped binaries must still run.
"${stage}/bin/heyaki-relay" --version >/dev/null
"${stage}/bin/heyaki-tui" --version >/dev/null

# ---------------------------------------------------------------------------
# Tarballs.
# ---------------------------------------------------------------------------
if [ "${skip_tarball}" -eq 0 ]; then
  echo "== creating tarballs in ${output_dir}/dist"
  staging_dir="${work}/tar-root"
  mkdir -p "${staging_dir}/${package_root}"
  cp -a "${stage}/." "${staging_dir}/${package_root}/"
  tar -C "${staging_dir}" -czf "${output_dir}/dist/${package_root}.tar.gz" \
    "${package_root}"
  mkdir -p "${staging_dir}/${package_root}-dbg"
  cp -a "${dbg}/." "${staging_dir}/${package_root}-dbg/"
  tar -C "${staging_dir}" -czf "${output_dir}/dist/${package_root}-dbg.tar.gz" \
    "${package_root}-dbg"
  (
    cd "${output_dir}/dist"
    sha256sum "${package_root}.tar.gz" "${package_root}-dbg.tar.gz" > SHA256SUMS
  )

  # Extracted tarball smoke: the clean-machine install form.
  extract_dir="${work}/extract"
  mkdir -p "${extract_dir}"
  tar -C "${extract_dir}" -xzf "${output_dir}/dist/${package_root}.tar.gz"
  "${extract_dir}/${package_root}/bin/heyaki-relay" --version >/dev/null
  [ -f "${extract_dir}/${package_root}/share/heyaki/coturn/turnserver.conf" ]
fi

# ---------------------------------------------------------------------------
# Uninstall simulation: manifest-driven removal must leave no regular files.
# ---------------------------------------------------------------------------
uninstall_log="${work}/uninstall.log"
if ! cmake -DHEYAKI_INSTALL_MANIFEST="${manifest}" \
      -P "${script_root}/cmake/cmake_uninstall.cmake" >"${uninstall_log}" 2>&1; then
  tail -20 "${uninstall_log}" >&2
  echo "package_release: uninstall script failed" >&2
  exit 1
fi
leftover="$(find "${stage}" -type f | wc -l)"
[ "${leftover}" -eq 0 ] || {
  echo "package_release: uninstall left ${leftover} regular files behind:" >&2
  find "${stage}" -type f >&2
  exit 1
}
echo "== uninstall verification clean (0 regular files left)"

if [ "${skip_tarball}" -eq 0 ]; then
  echo "PACKAGE_OK ${package_root} symbols=${symbol_file_count}"
else
  echo "PACKAGE_OK ${package_root} symbols=${symbol_file_count} (no tarball)"
fi
