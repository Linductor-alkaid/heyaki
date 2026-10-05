#!/usr/bin/env bash
# Run the Heyaki Android integration smoke on a device or emulator (M11-07).
#
# Pushes the NDK-built heyaki_android_smoke binary over adb, executes it in an
# app-scoped directory under /data/local/tmp, and reports PASS/FAIL. The
# binary is self-contained (static libc++); no app installation is needed.
#
# Usage:
#   scripts/run_android_smoke.sh --binary build-android/x86_64/install/bin/heyaki_android_smoke \
#       [--serial emulator-5554] [--keep]
#
# The serial may also come from ANDROID_SERIAL. ANDROID_HOME/adb must be on
# PATH or ANDROID_HOME must point at the SDK.

set -euo pipefail

SERIAL="${ANDROID_SERIAL:-}"
BINARY=""
DEVICE_DIR="/data/local/tmp/heyaki-smoke"
CLEANUP="true"

usage() {
  echo "Usage: $0 --binary <path/to/heyaki_android_smoke> [--serial <serial>] [--keep]"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      BINARY="$2"
      shift 2
      ;;
    --serial)
      SERIAL="$2"
      shift 2
      ;;
    --keep)
      CLEANUP="false"
      shift
      ;;
    *)
      echo "Unknown option: $1"
      usage
      ;;
  esac
done

[[ -n "$BINARY" && -f "$BINARY" ]] || { echo "Error: --binary is required and must exist"; usage; }

if ! command -v adb >/dev/null 2>&1 && [[ -n "${ANDROID_HOME:-}" && -x "$ANDROID_HOME/platform-tools/adb" ]]; then
  PATH="$ANDROID_HOME/platform-tools:$PATH"
fi
command -v adb >/dev/null 2>&1 || { echo "Error: adb not found"; exit 1; }

ADB=(adb)
[[ -n "$SERIAL" ]] && ADB+=(-s "$SERIAL")
"${ADB[@]}" get-state >/dev/null

# Wait for boot completion (a freshly started emulator may still be booting).
boot_done="$("${ADB[@]}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)"
for _ in $(seq 1 60); do
  [[ "$boot_done" == "1" ]] && break
  sleep 2
  boot_done="$("${ADB[@]}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)"
done
[[ "$boot_done" == "1" ]] || { echo "Error: device did not finish booting"; exit 1; }

name="$(basename -- "$BINARY")"
remote="$DEVICE_DIR/$name"

cleanup() {
  if [[ "$CLEANUP" == "true" ]]; then
    "${ADB[@]}" shell rm -rf "$DEVICE_DIR" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "==> push $name"
"${ADB[@]}" push "$BINARY" "$remote" >/dev/null
"${ADB[@]}" shell chmod 755 "$remote"

echo "==> run $name"
set +e
output="$("${ADB[@]}" shell "$DEVICE_DIR/$name $DEVICE_DIR" 2>&1)"
status=$?
set -e
printf '%s\n' "$output"

if [[ $status -eq 0 && "$output" == *HEYAKI_ANDROID_SMOKE_OK* ]]; then
  echo "<== PASS $name"
  exit 0
fi
echo "<== FAIL $name (exit $status)"
exit 1
