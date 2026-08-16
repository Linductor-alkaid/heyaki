#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

# M3B exit-condition harness:
# 1. create one local profile used by heyaki-tui and an independent library demo;
# 2. complete relay enrollment from the existing profile through heyaki-tui;
# 3. restart TUI (--status) and the library demo; both must auto-login without input;
# 4. verify both processes use the same DeviceId and different EndpointId.

[[ "$(uname -s)" == "Linux" ]] || { printf 'SKIP: Linux pty/network harness only\n'; exit 77; }

relay_bin=${HEYAKI_RELAY_BIN:-}
tui_bin=${HEYAKI_TUI_BIN:-}
demo_bin=${HEYAKI_DEMO_BIN:-}
work_dir=${HEYAKI_M3B_HARNESS_DIR:-}

usage() {
  cat <<USAGE_EOF
Usage: $0 --relay-bin PATH --tui-bin PATH --demo-bin PATH [--work-dir PATH]
USAGE_EOF
}

while (($# > 0)); do
  case "$1" in
    --relay-bin) relay_bin=${2:?missing relay-bin value}; shift 2;;
    --tui-bin) tui_bin=${2:?missing tui-bin value}; shift 2;;
    --demo-bin) demo_bin=${2:?missing demo-bin value}; shift 2;;
    --work-dir) work_dir=${2:?missing work-dir value}; shift 2;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 2;;
  esac
done

for command_name in openssl python3; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    printf 'SKIP: %s is unavailable\n' "${command_name}"
    exit 77
  }
done
[[ -n "${relay_bin}" && -x "${relay_bin}" ]] || { printf 'SKIP: relay binary unavailable\n'; exit 77; }
[[ -n "${tui_bin}" && -x "${tui_bin}" ]] || { printf 'SKIP: tui binary unavailable\n'; exit 77; }
[[ -n "${demo_bin}" && -x "${demo_bin}" ]] || { printf 'SKIP: demo binary unavailable\n'; exit 77; }
[[ -n "${work_dir}" ]] && mkdir -p "${work_dir}"
work_dir=$(mktemp -d "${work_dir:-/tmp}/heyaki-m3b-onboarding.XXXXXX")
chmod 700 "${work_dir}"
state_dir="${work_dir}/state"
mkdir -p "${state_dir}"
profile_db="${state_dir}/heyaki/profiles/default/profile.sqlite"
relay_db="${work_dir}/relay.sqlite"
relay_pid=""
demo_pid=""
proxy_pid=""

cleanup() {
  set +e
  [[ -n "${demo_pid}" ]] && kill -TERM "${demo_pid}" 2>/dev/null
  [[ -n "${proxy_pid}" ]] && kill -TERM "${proxy_pid}" 2>/dev/null
  [[ -n "${relay_pid}" ]] && kill -TERM "${relay_pid}" 2>/dev/null
  sleep 0.3
  [[ -n "${demo_pid}" ]] && kill -KILL "${demo_pid}" 2>/dev/null
  [[ -n "${relay_pid}" ]] && kill -KILL "${relay_pid}" 2>/dev/null
  rm -rf "${work_dir}"
}
trap cleanup EXIT

# CA and server certificate. TUI/demo use OpenSSL default trust with SSL_CERT_FILE.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -set_serial 1 \
  -subj "/CN=heyaki-relay-test" \
  -keyout "${work_dir}/ca-key.pem" -out "${work_dir}/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -subj "/CN=127.0.0.1" \
  -keyout "${work_dir}/relay-key.pem" -out "${work_dir}/relay.csr" >/dev/null 2>&1
printf 'subjectAltName=IP:127.0.0.1\n' > "${work_dir}/san.ext"
openssl x509 -req -in "${work_dir}/relay.csr" -CA "${work_dir}/ca.pem" \
  -CAkey "${work_dir}/ca-key.pem" -CAcreateserial -days 1 \
  -extfile "${work_dir}/san.ext" \
  -out "${work_dir}/relay-cert.pem" >/dev/null 2>&1

port=$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
PY
)
relay_url="wss://127.0.0.1:${port}"
tenant="tenant-a"
token="TEST-ONLY-m3b-onboarding-token-0123456789"
expiry=$(python3 - <<'PY'
import time
print(int(time.time() * 1000) + 120000)
PY
)

mkdir -p "$(dirname "${profile_db}")"
chmod 700 "${state_dir}" "${state_dir}/heyaki" "${state_dir}/heyaki/profiles" "${state_dir}/heyaki/profiles/default"
"${demo_bin}" init-profile "${profile_db}" org.heyaki.tui org.heyaki.m3b-demo \
  >"${work_dir}/init.log"
"${demo_bin}" seed-token "${relay_db}" "${tenant}" "${token}" "${expiry}"

cat >"${work_dir}/relay.conf" <<RELAY_EOF
listen_address = 127.0.0.1
listen_port = ${port}
tls_certificate_file = ${work_dir}/relay-cert.pem
tls_private_key_file = ${work_dir}/relay-key.pem
database_file = ${relay_db}
handshake_timeout_milliseconds = 2000
shutdown_timeout_milliseconds = 2000
RELAY_EOF

XDG_STATE_HOME="${state_dir}" SSL_CERT_FILE="${work_dir}/ca.pem" \
  "${relay_bin}" --config "${work_dir}/relay.conf" >"${work_dir}/relay.log" 2>&1 &
relay_pid=$!
for _ in $(seq 1 50); do
  if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
    break
  fi
  sleep 0.1
done

python3 "${script_dir}/tcp_capture_proxy.py" 127.0.0.1 0 127.0.0.1 "${port}"   "${work_dir}/wss-capture.bin" >"${work_dir}/proxy.log" 2>&1 &
proxy_pid=$!
proxy_port=""
for _ in $(seq 1 50); do
  proxy_port=$(sed -n 's/^PROXY_PORT=//p' "${work_dir}/proxy.log" 2>/dev/null | tail -1)
  [[ -n "${proxy_port}" ]] && break
  sleep 0.1
done
[[ -n "${proxy_port}" ]] || { cat "${work_dir}/proxy.log"; printf 'capture proxy did not start\n'; exit 1; }
proxy_url="wss://127.0.0.1:${proxy_port}"

XDG_STATE_HOME="${state_dir}" SSL_CERT_FILE="${work_dir}/ca.pem" \
  HEYAKI_TUI_BIN="${tui_bin}" HEYAKI_RELAY_URL="${proxy_url}" \
  HEYAKI_TENANT="${tenant}" HEYAKI_TOKEN="${token}" \
  HEYAKI_TUI_DRIVE_LOG="${work_dir}/tui-enroll.log" \
  python3 "${script_dir}/drive_tui_relay_enrollment.py" || {
    cat "${work_dir}/tui-enroll.log"
    printf 'TUI relay enrollment failed\n'
    exit 1
  }

XDG_STATE_HOME="${state_dir}" SSL_CERT_FILE="${work_dir}/ca.pem" \
  "${demo_bin}" run "${profile_db}" org.heyaki.m3b-demo 8000 \
  >"${work_dir}/demo.log" 2>&1 &
demo_pid=$!
ready=false
for _ in $(seq 1 100); do
  if grep -q '^RELAY=ready$' "${work_dir}/demo.log" 2>/dev/null; then
    ready=true
    break
  fi
  if ! kill -0 "${demo_pid}" 2>/dev/null; then
    cat "${work_dir}/tui-enroll.log"
    cat "${work_dir}/init.log"
    cat "${work_dir}/demo.log"
    printf 'library demo exited before relay-ready\n'
    exit 1
  fi
  sleep 0.1
done
if [[ "${ready}" != "true" ]]; then
  cat "${work_dir}/demo.log"
  printf 'library demo did not auto-login\n'
  exit 1
fi

XDG_STATE_HOME="${state_dir}" SSL_CERT_FILE="${work_dir}/ca.pem" \
  "${tui_bin}" --profile default --status >"${work_dir}/tui-status.log" 2>&1
grep -q 'RELAY   ready' "${work_dir}/tui-status.log" || {
  cat "${work_dir}/tui-status.log"
  printf 'TUI restart did not auto-login\n'
  exit 1
}

tui_device=$(grep -m1 'device=' "${work_dir}/tui-status.log" | sed 's/.*device=\([^ ]*\).*/\1/')
tui_endpoint=$(grep -m1 'endpoint=' "${work_dir}/tui-status.log" | sed 's/.*endpoint=\([^ ]*\).*/\1/')
demo_device=$(grep -m1 '^DEVICE=' "${work_dir}/demo.log" | cut -d= -f2-)
demo_endpoint=$(grep -m1 '^ENDPOINT=' "${work_dir}/demo.log" | cut -d= -f2-)
[[ -n "${tui_device}" && "${tui_device}" == "${demo_device}" ]] || {
  cat "${work_dir}/tui-status.log"
  cat "${work_dir}/demo.log"
  printf 'TUI and demo DeviceId mismatch: %s != %s\n' "${tui_device}" "${demo_device}"
  exit 1
}
[[ -n "${tui_endpoint}" && "${tui_endpoint}" != "${demo_endpoint}" ]] || {
  cat "${work_dir}/tui-status.log"
  cat "${work_dir}/demo.log"
  printf 'TUI and demo EndpointId are not distinct: %s == %s\n' "${tui_endpoint}" "${demo_endpoint}"
  exit 1
}

wait "${demo_pid}"
demo_pid=""

if grep -aEq 'heyaki-m3b-demo-password|argon2|PRIVATE KEY|BEGIN [A-Z ]*PRIVATE KEY' \
    "${relay_db}" "${work_dir}/relay.log" "${work_dir}/wss-capture.bin"; then
  printf 'secret artifact found in relay DB/log/WSS capture\n'
  exit 1
fi

printf 'M3B_ONBOARDING_OK device=%s tui_endpoint=%s demo_endpoint=%s\n' \
  "${demo_device}" "${tui_endpoint}" "${demo_endpoint}"
