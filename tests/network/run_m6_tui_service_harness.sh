#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

# M6 exit-condition harness: two TUI instances complete pairing, exchange a
# peer_acked typed message, and run a unary RPC end to end through the public
# TUI views — no private protocol shortcuts.

[[ "$(uname -s)" == "Linux" ]] || { printf 'SKIP: Linux pty/network harness only\n'; exit 77; }

tui_bin=${HEYAKI_TUI_BIN:-}
work_dir=${HEYAKI_M6_TUI_HARNESS_DIR:-}

usage() {
  cat <<USAGE_EOF
Usage: $0 --tui-bin PATH [--work-dir PATH]
USAGE_EOF
}

while (($# > 0)); do
  case "$1" in
    --tui-bin) tui_bin=${2:?missing tui-bin value}; shift 2;;
    --work-dir) work_dir=${2:?missing work-dir value}; shift 2;;
    *) usage >&2; exit 2;;
  esac
done

[[ -n "${tui_bin}" ]] || { usage >&2; exit 2; }
[[ -x "${tui_bin}" ]] || { printf 'tui binary not executable: %s\n' "${tui_bin}" >&2; exit 2; }
command -v python3 >/dev/null || { printf 'SKIP: python3 required\n'; exit 77; }

[[ -n "${work_dir}" ]] && mkdir -p "${work_dir}"
work_dir=$(mktemp -d "${work_dir:-/tmp}/heyaki-m6-tui-service.XXXXXX")
chmod 700 "${work_dir}"
state_a="${work_dir}/state-a"
state_b="${work_dir}/state-b"
mkdir -p "${state_a}" "${state_b}"
chmod 700 "${state_a}" "${state_b}"

cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

HEYAKI_TUI_BIN="${tui_bin}" \
HEYAKI_TUI_STATE_A="${state_a}" \
HEYAKI_TUI_STATE_B="${state_b}" \
HEYAKI_M6_TUI_LOG="${work_dir}/tui-service.log" \
  python3 "${script_dir}/drive_m6_tui_service.py"
