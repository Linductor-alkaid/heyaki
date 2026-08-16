#!/usr/bin/env bash
set -euo pipefail

# Heyaki M3B-10/11 local TURN REST allocation probe.
#
# Starts coturn with the checked-in resource-policy template (ports above 1024,
# no root required on Linux), obtains a TURN REST API allocation with the
# Heyaki username contract `<expiry>:<tenant>:<DeviceId>`, and verifies that
# relayed data is admitted by the allocation. It never embeds coturn in
# heyaki-relay and never writes the secret to a log.

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
coturn_root=${HEYAKI_COTURN_ROOT:-}
turnserver_bin=${HEYAKI_TURNSERVER_BIN:-}
uclient_bin=${HEYAKI_UCLIENT_BIN:-}
loader_bin=${HEYAKI_COTURN_LOADER_BIN:-}
listen_ip=${HEYAKI_TURN_LISTEN_ADDRESS:-"127.0.0.1"}
advertised_ip=${HEYAKI_TURN_ADVERTISED_ADDRESS:-"127.0.0.1"}
peer_ip=${HEYAKI_TURN_PEER_ADDRESS:-"8.8.8.8"}
peer_port=${HEYAKI_TURN_PEER_PORT:-9}
turn_port=${HEYAKI_TURN_PORT:-3478}
check_only=false
keep=false

usage() {
  cat <<USAGE_EOF
Usage: $0 [--check-only] [--keep]

Environment:
  HEYAKI_COTURN_ROOT          Extracted coturn image rootfs (optional; enables the
                              image's own dynamic loader and pinned libraries).
  HEYAKI_TURNSERVER_BIN       Override turnserver path.
  HEYAKI_UCLIENT_BIN          Override turnutils_uclient path.
  HEYAKI_COTURN_LOADER_BIN    Override dynamic loader path.
  HEYAKI_TURN_SECRET          static-auth-secret (never logged).
  HEYAKI_TURN_LISTEN_ADDRESS  Listener address, default 127.0.0.1.
  HEYAKI_TURN_ADVERTISED_ADDRESS  Advertised address, default 127.0.0.1.
  HEYAKI_TURN_PEER_ADDRESS    Peer address used by the allocation, default 8.8.8.8.
  HEYAKI_TURN_PEER_PORT       Peer port, default 9.
  HEYAKI_TURN_PORT            TURN client port, default 3478.
USAGE_EOF
}

while (($# > 0)); do
  case "$1" in
    --check-only) check_only=true; shift;;
    --keep) keep=true; shift;;
    -h|--help) usage; exit 0;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 2;;
  esac
done

log() { printf '[heyaki-turn-allocation] %s\n' "$*"; }
skip() { printf 'SKIP: %s\n' "$*"; exit 77; }

if [[ -n "${coturn_root}" ]]; then
  [[ -d "${coturn_root}" ]] || skip "HEYAKI_COTURN_ROOT is not a directory"
  [[ -z "${turnserver_bin}" ]] && turnserver_bin="${coturn_root}/usr/bin/turnserver"
  [[ -z "${uclient_bin}" ]] && uclient_bin="${coturn_root}/usr/bin/turnutils_uclient"
  if [[ -z "${loader_bin}" ]]; then
    loader_bin=$(find "${coturn_root}" -path '*/ld-linux-x86-64.so.2' -type f 2>/dev/null | head -1 || true)
  fi
  [[ -x "${turnserver_bin}" ]] || skip "turnserver is unavailable: ${turnserver_bin}"
  [[ -x "${uclient_bin}" ]] || skip "turnutils_uclient is unavailable: ${uclient_bin}"
  [[ -z "${loader_bin}" || -x "${loader_bin}" ]] || skip "dynamic loader is unavailable: ${loader_bin}"
else
  [[ -z "${turnserver_bin}" ]] && turnserver_bin=$(command -v turnserver || true)
  [[ -z "${uclient_bin}" ]] && uclient_bin=$(command -v turnutils_uclient || true)
  [[ -n "${turnserver_bin}" && -x "${turnserver_bin}" ]] || skip "turnserver is unavailable"
  [[ -n "${uclient_bin}" && -x "${uclient_bin}" ]] || skip "turnutils_uclient is unavailable"
fi
command -v openssl >/dev/null 2>&1 || skip "openssl is unavailable"

run_coturn_bin() {
  if [[ -n "${loader_bin}" && -n "${coturn_root}" ]]; then
    "${loader_bin}" --library-path "${coturn_root}/usr/lib/x86_64-linux-gnu" "$@"
  else
    "$@"
  fi
}

if [[ "${check_only}" == "true" ]]; then
  version=$(run_coturn_bin "${turnserver_bin}" --version 2>&1 | tail -1 || true)
  log "ALLOCATION_PROBE_CHECK_OK turnserver=${turnserver_bin} uclient=${uclient_bin} version=${version}"
  exit 0
fi

work_dir=$(mktemp -d)
turn_pid=""
cleanup() {
  set +e
  [[ -n "${turn_pid}" ]] && kill -TERM "${turn_pid}" 2>/dev/null
  sleep 0.2
  [[ -n "${turn_pid}" ]] && kill -KILL "${turn_pid}" 2>/dev/null
  if [[ "${keep}" != "true" ]]; then
    rm -rf "${work_dir}"
  else
    log "artifacts kept in ${work_dir}"
  fi
}
trap cleanup EXIT

secret=${HEYAKI_TURN_SECRET:-$(openssl rand -base64 24)}
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${work_dir}/turn-key.pem" \
  -out "${work_dir}/turn-cert.pem" \
  -subj "/CN=heyaki-turn.invalid" -days 1 -set_serial 1 >/dev/null 2>&1

sed -e "s#__TURN_SECRET__#${secret}#" \
    -e "s#__ADVERTISED_ADDRESS__#${advertised_ip}#" \
    -e "s#__LISTEN_ADDRESS__#${listen_ip}#" \
    -e "s#/etc/letsencrypt/live/heyaki.invalid/fullchain.pem#${work_dir}/turn-cert.pem#" \
    -e "s#/etc/letsencrypt/live/heyaki.invalid/privkey.pem#${work_dir}/turn-key.pem#" \
    -e "s#/var/log/coturn/turnserver.log#${work_dir}/turn.log#" \
    "${script_dir}/turnserver.conf" > "${work_dir}/turnserver.conf"

run_coturn_bin "${turnserver_bin}" -c "${work_dir}/turnserver.conf" \
  >"${work_dir}/turn.stdout.log" 2>&1 &
turn_pid=$!

ready=false
for _ in $(seq 1 100); do
  if grep -Rqs "Relay ports initialization done" "${work_dir}" 2>/dev/null; then
    ready=true
    break
  fi
  if ! kill -0 "${turn_pid}" 2>/dev/null; then
    cat "${work_dir}/turn.stdout.log"
    log "coturn exited before initialization"
    exit 1
  fi
  sleep 0.1
done
if [[ "${ready}" != "true" ]]; then
  cat "${work_dir}/turn.stdout.log"
  log "coturn did not finish relay port initialization"
  exit 1
fi

expiry=$(( $(date +%s) + 600 ))
username="${expiry}:tenant-a:hy1_testdevice"
uclient_output="${work_dir}/uclient.log"
set +e
run_coturn_bin "${uclient_bin}" -t -X -n 2 -l 32 \
  -e "${peer_ip}" -r "${peer_port}" \
  -u "${username}" -W "${secret}" -p "${turn_port}" "${listen_ip}" \
  >"${uclient_output}" 2>&1
uclient_rc=$?
set -e

cat "${uclient_output}"
if [[ ${uclient_rc} -ne 0 ]] || \
   ! grep -Eq "tot_send_msgs=[1-9][0-9]*" "${uclient_output}" || \
   grep -q "Cannot complete Allocation" "${uclient_output}"; then
  log "TURN allocation probe failed"
  exit 1
fi

version=$(run_coturn_bin "${turnserver_bin}" --version 2>&1 | tail -1 || true)
secret_in_log=$(grep -Rls -- "${secret}" "${work_dir}" 2>/dev/null | grep -v '/turnserver.conf$' || true)
if [[ -n "${secret_in_log}" ]]; then
  log "ERROR: coturn log contains the static-auth-secret"
  exit 1
fi
log "ALLOCATION_OK version=${version} username_contract=expiry:tenant:DeviceId"
