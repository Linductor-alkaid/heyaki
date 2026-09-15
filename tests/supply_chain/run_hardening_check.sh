#!/usr/bin/env bash
set -euo pipefail
# readelf output is localized on some hosts; the assertions below parse the
# canonical English field names.
export LC_ALL=C

# M9-14 binary hardening verification. Asserts the ELF mitigations that
# HEYAKI_HARDENING is supposed to produce on every shipped Linux executable:
#
#   PIE            ELF header Type is DYN (position independent executable)
#   NX stack       GNU_STACK program header carries no execute flag
#   full RELRO     GNU_RELRO segment present AND BIND_NOW in dynamic flags
#   stack canary   __stack_chk_fail referenced (stack protector active)
#   FORTIFY        at least one __*_chk symbol from <bits/stdio2/string2.h>
#                  (Release configurations only, --expect-fortify)
#
# Sanitizer builds are excluded at CTest registration time; this script only
# checks what it can see in the file. Any failed assertion fails the run with
# a HARDENING_FAIL line naming the binary and the missing property.

script_name=$(basename -- "$0")

usage() {
  cat <<USAGE_EOF
Usage: $0 [--expect-fortify] BIN [BIN...]

Verifies ELF hardening properties (PIE, NX stack, full RELRO, stack canary,
and optionally FORTIFY) of each BIN. Exits non-zero on the first binary that
misses any expected property.
USAGE_EOF
}

expect_fortify=0
if [[ "${1:-}" == "--expect-fortify" ]]; then
  expect_fortify=1
  shift
fi
(($# > 0)) || { usage >&2; exit 2; }

command -v readelf >/dev/null 2>&1 || {
  printf 'HARDENING_FAIL: readelf is required for the hardening check\n' >&2
  exit 2
}

failures=0
check_binary() {
  local bin=$1
  local output

  if [[ ! -f ${bin} ]]; then
    printf 'HARDENING_FAIL: %s: no such file\n' "${bin}" >&2
    failures=$((failures + 1))
    return
  fi

  # PIE: an executable linked with -pie has ELF type DYN.
  output=$(readelf -h "${bin}")
  if ! grep -q '^  Type:.*DYN' <<<"${output}"; then
    printf 'HARDENING_FAIL: %s: not PIE (ELF type is not DYN)\n' "${bin}" >&2
    failures=$((failures + 1))
  fi

  # NX stack: GNU_STACK must be readable/writable but not executable.
  output=$(readelf -W -l "${bin}")
  local stack_flags
  stack_flags=$(awk '$1 == "GNU_STACK" { print $7 }' <<<"${output}")
  if [[ -z ${stack_flags} ]]; then
    printf 'HARDENING_FAIL: %s: no GNU_STACK program header\n' "${bin}" >&2
    failures=$((failures + 1))
  elif [[ ${stack_flags} != "RW" ]]; then
    printf 'HARDENING_FAIL: %s: GNU_STACK flags are %s, expected RW (NX)\n' \
      "${bin}" "${stack_flags}" >&2
    failures=$((failures + 1))
  fi

  # Full RELRO: a GNU_RELRO segment plus immediate binding.
  if ! grep -q 'GNU_RELRO' <<<"${output}"; then
    printf 'HARDENING_FAIL: %s: no GNU_RELRO segment\n' "${bin}" >&2
    failures=$((failures + 1))
  fi
  local dynamic
  dynamic=$(readelf -W -d "${bin}")
  if ! grep -Eq '(BIND_NOW|FLAGS_1.*NOW|FLAGS.*NOW)' <<<"${dynamic}"; then
    printf 'HARDENING_FAIL: %s: no BIND_NOW (full RELRO)\n' "${bin}" >&2
    failures=$((failures + 1))
  fi

  # Stack canary: stack-protected objects reference __stack_chk_fail.
  local symbols
  symbols=$(readelf -W -s "${bin}")
  if ! grep -q '__stack_chk_fail' <<<"${symbols}"; then
    printf 'HARDENING_FAIL: %s: no __stack_chk_fail reference (stack protector)\n' \
      "${bin}" >&2
    failures=$((failures + 1))
  fi

  # FORTIFY: optimized builds must reference at least one checked variant.
  if ((expect_fortify)); then
    if ! grep -Eq '__[a-zA-Z0-9_]+_chk' <<<"${symbols}"; then
      printf 'HARDENING_FAIL: %s: no FORTIFY __*_chk symbols in optimized build\n' \
        "${bin}" >&2
      failures=$((failures + 1))
    fi
  fi

  local fortify_note=""
  if ((expect_fortify)); then
    fortify_note=", fortify"
  fi
  printf 'HARDENING_OK: %s (pie, nx, full-relro, canary%s)\n' \
    "${bin}" "${fortify_note}"
}

for binary in "$@"; do
  check_binary "${binary}"
done

if ((failures > 0)); then
  printf 'HARDENING_FAIL: %d assertion(s) failed\n' "${failures}" >&2
  exit 1
fi
exit 0
