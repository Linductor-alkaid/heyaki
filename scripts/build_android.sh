#!/usr/bin/env bash
# Heyaki Android (NDK) cross-build script (M11-01).
#
# Builds the C++20 core libraries (heyaki-core, profile, client, services,
# socks, transport_webrtc) against the NDK toolchain. Apps, demos, fuzzers,
# and host test targets are desktop-only and are excluded from this build.
#
# Usage:
#   scripts/build_android.sh --ndk /path/to/android-ndk [options]
#
# The NDK path may also come from the ANDROID_NDK_HOME environment variable.
# The API floor is android-24: the POSIX interface enumeration uses
# getifaddrs/if_nametoindex, which bionic provides from API 24 (M11 plan A3).

set -euo pipefail

BUILD_TYPE="${BUILD_TYPE:-Release}"
ANDROID_ABIS="${ANDROID_ABIS:-arm64-v8a,x86_64}"
ANDROID_API="${ANDROID_API:-24}"
OUTPUT_DIR="${OUTPUT_DIR:-build-android}"
NDK_PATH="${ANDROID_NDK_HOME:-}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

usage() {
  echo "Usage: $0 [--ndk /path/to/android-ndk] [--abi arm64-v8a,x86_64] [--api 24]"
  echo "          [--build-type Release|Debug] [--output-dir build-android]"
  echo "          [--jobs N]"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ndk)
      NDK_PATH="$2"
      shift 2
      ;;
    --abi)
      ANDROID_ABIS="$2"
      shift 2
      ;;
    --api)
      ANDROID_API="$2"
      shift 2
      ;;
    --build-type)
      BUILD_TYPE="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --jobs)
      JOBS="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      usage
      ;;
  esac
done

if [[ -z "$NDK_PATH" ]]; then
  echo "Error: NDK path is required. Use --ndk or set ANDROID_NDK_HOME."
  usage
fi

TOOLCHAIN_FILE="$NDK_PATH/build/cmake/android.toolchain.cmake"
if [[ ! -f "$TOOLCHAIN_FILE" ]]; then
  echo "Error: Android toolchain file not found: $TOOLCHAIN_FILE"
  exit 1
fi

if [[ "$ANDROID_API" -lt 24 ]]; then
  echo "Error: --api must be >= 24 (bionic getifaddrs floor for the LAN route)."
  exit 1
fi

command -v cmake >/dev/null 2>&1 || { echo "Error: CMake not found"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "========================================"
echo "Heyaki Android Build (M11)"
echo "========================================"
echo "NDK:         $NDK_PATH"
echo "ABIs:        $ANDROID_ABIS"
echo "Android API: $ANDROID_API"
echo "Build Type:  $BUILD_TYPE"
echo "Output Dir:  $OUTPUT_DIR"
echo "CMake:       $(cmake --version | head -n 1)"
echo "========================================"
echo ""

IFS=',' read -ra ABI_LIST <<< "$ANDROID_ABIS"

for abi in "${ABI_LIST[@]}"; do
  [[ -z "$abi" ]] && continue
  build_dir="$OUTPUT_DIR/$abi"

  echo "----------------------------------------"
  echo "Configuring $abi"
  echo "----------------------------------------"
  cmake -S "$PROJECT_ROOT" -B "$build_dir" \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
    -DANDROID_ABI="$abi" \
    -DANDROID_PLATFORM="android-$ANDROID_API" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DHEYAKI_BUILD_APPS=OFF \
    -DHEYAKI_AUTO_INSTALL=OFF \
    -DCMAKE_INSTALL_PREFIX="$build_dir/install"

  echo "Building $abi..."
  cmake --build "$build_dir" -j "$JOBS"

  echo "Installing $abi..."
  cmake --install "$build_dir"
  echo "$abi completed."
  echo ""
done

echo "========================================"
echo "Heyaki Android build completed!"
echo "Artifacts under: $OUTPUT_DIR/<abi>/install"
echo "========================================"
