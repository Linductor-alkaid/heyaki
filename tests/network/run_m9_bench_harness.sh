#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

# M9-10 benchmark harness (loopback relay, no root, no coturn):
#
#   Phase R  registration + direct-connect P95 — N fresh process pairs
#            (same enrolled profiles, clean node state per iteration).
#            Gates: login P95 (v1 acceptance < 2s), dial→authenticated P95
#            (< 3s), every cycle authenticates direct_host.
#   Phase T  TURN-fallback P95 — same loop with forced TURN through two
#            heyaki-test-turn-server instances (static credentials).
#            Gates: dial→authenticated P95 (< 5s), data path turn_udp.
#   Phase L  long-lived suite — one bench initiator against three bench
#            responders (fan-out subscribers, shell profile):
#            message RTT, sequential/concurrent RPC, event fan-out,
#            single/concurrent file throughput, shell ping latency idle
#            and under a bulk push. Gates: zero failures, P95 sanity
#            bounds, complete fan-out delivery, files committed.
#   Relay    footprint scrapes around the phases (signaling counters,
#            RSS/fd, endpoint/lease tables) — informational deltas plus
#            boundedness gates at the end.
#
# Absolute numbers are the point of M9-10 (they feed the M9-11 parameter
# freeze and the v1 acceptance record); the gates are the v1 acceptance
# targets plus generous sanity bounds, not tight SLAs.
#
# Env knobs:
#   HEYAKI_BENCH_CYCLES       (default 6)    Phase R / Phase T iterations
#   HEYAKI_BENCH_SUBSCRIBERS  (default 3)    Phase L fan-out receivers
#   HEYAKI_BENCH_MSG_N        (default 200)  sequential message samples
#   HEYAKI_BENCH_RPC_N        (default 200)  sequential RPC samples
#   HEYAKI_BENCH_RPC_CONC_N   (default 300)  concurrent RPC completions
#   HEYAKI_BENCH_FANOUT_N     (default 100)  events per fan-out run
#   HEYAKI_BENCH_FILE_BYTES   (default 32MiB) single/under-shell push size
#   HEYAKI_BENCH_FILE_MULTI_BYTES (default 8MiB) per concurrent push
#   HEYAKI_BENCH_LOGIN_P95_MS    (default 2000) registration gate
#   HEYAKI_BENCH_CONNECT_P95_MS  (default 3000) direct-connect gate
#   HEYAKI_BENCH_TURN_P95_MS     (default 5000) TURN-fallback gate
#   HEYAKI_BENCH_MSG_P95_MS      (default 500)  message/RPC sanity gate
#   HEYAKI_BENCH_WORK_DIR        keep-everything work dir
#
# Gated like the soak harness: SKIP 77 unless HEYAKI_REQUIRE_M9_BENCH=1 so
# default local/CI ctest suites and sanitizer presets stay fast.

[[ "${HEYAKI_REQUIRE_M9_BENCH:-0}" == "1" ]] || {
  printf 'SKIP: set HEYAKI_REQUIRE_M9_BENCH=1 to run the M9 bench harness\n'
  exit 77
}
[[ "$(uname -s)" == "Linux" ]] || { printf 'SKIP: Linux-only bench harness\n'; exit 77; }

relay_bin=${HEYAKI_RELAY_BIN:-}
matrix_bin=${HEYAKI_MATRIX_BIN:-}
demo_bin=${HEYAKI_DEMO_BIN:-}
turn_bin=${HEYAKI_TURN_BIN:-}
work_dir=${HEYAKI_BENCH_WORK_DIR:-}

usage() {
  cat <<USAGE_EOF
Usage: $0 --relay-bin PATH --matrix-bin PATH --demo-bin PATH --turn-bin PATH
          [--work-dir PATH]
USAGE_EOF
}

while (($# > 0)); do
  case "$1" in
    --relay-bin) relay_bin=${2:?missing relay-bin value}; shift 2;;
    --matrix-bin) matrix_bin=${2:?missing matrix-bin value}; shift 2;;
    --demo-bin) demo_bin=${2:?missing demo-bin value}; shift 2;;
    --turn-bin) turn_bin=${2:?missing turn-bin value}; shift 2;;
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
for binary in "${relay_bin}" "${matrix_bin}" "${demo_bin}" "${turn_bin}"; do
  [[ -n "${binary}" && -x "${binary}" ]] || {
    printf 'SKIP: required binary unavailable (%s)\n' "${binary}"
    exit 77
  }
done

cycles=${HEYAKI_BENCH_CYCLES:-6}
subscribers=${HEYAKI_BENCH_SUBSCRIBERS:-3}
msg_n=${HEYAKI_BENCH_MSG_N:-200}
rpc_n=${HEYAKI_BENCH_RPC_N:-200}
rpc_conc_n=${HEYAKI_BENCH_RPC_CONC_N:-300}
fanout_n=${HEYAKI_BENCH_FANOUT_N:-100}
file_bytes=${HEYAKI_BENCH_FILE_BYTES:-33554432}
file_multi_bytes=${HEYAKI_BENCH_FILE_MULTI_BYTES:-8388608}
login_p95_ms=${HEYAKI_BENCH_LOGIN_P95_MS:-2000}
connect_p95_ms=${HEYAKI_BENCH_CONNECT_P95_MS:-3000}
turn_p95_ms=${HEYAKI_BENCH_TURN_P95_MS:-5000}
msg_p95_ms=${HEYAKI_BENCH_MSG_P95_MS:-500}

kept_work_dir=""
if [[ -n "${work_dir}" ]]; then
  mkdir -p "${work_dir}"
  # A persistent work dir (the CTest registration points at test-state)
  # must be idempotent across runs: wipe this harness's own subpaths so a
  # rerun does not trip profile_already_exists on stale databases.
  rm -rf "${work_dir}"/pair "${work_dir}"/phase-r "${work_dir}"/phase-t \
    "${work_dir}"/phase-l "${work_dir}"/relay.sqlite \
    "${work_dir}"/relay.sqlite-journal "${work_dir}"/relay.sqlite-wal \
    "${work_dir}"/relay.sqlite-shm "${work_dir}"/relay.conf \
    "${work_dir}"/relay.log "${work_dir}"/relay-baseline.txt \
    "${work_dir}"/relay-final.txt "${work_dir}"/relay-metrics-now.txt \
    "${work_dir}"/login-ms.txt "${work_dir}"/connect-r-ms.txt \
    "${work_dir}"/connect-t-ms.txt "${work_dir}"/path-r.txt \
    "${work_dir}"/path-t.txt "${work_dir}"/*.pem "${work_dir}"/*.csr \
    "${work_dir}"/*.srl "${work_dir}"/san.ext \
    "${work_dir}"/turn-a.log "${work_dir}"/turn-b.log 2>/dev/null || true
else
  work_dir=$(mktemp -d /tmp/heyaki-m9-bench.XXXXXX)
fi
chmod 700 "${work_dir}"

relay_pid=""
turn_a_pid=""
turn_b_pid=""
initiator_pid=""
responder_pid=""
declare -a responder_pids=()

cleanup() {
  set +e
  local pid=""
  for pid in "${responder_pids[@]:-}" "${responder_pid}" "${initiator_pid}" \
             "${turn_b_pid}" "${turn_a_pid}" "${relay_pid}"; do
    [[ -n "${pid}" ]] && kill -TERM "${pid}" 2>/dev/null
  done
  sleep 0.3
  for pid in "${responder_pids[@]:-}" "${responder_pid}" "${initiator_pid}" \
             "${turn_b_pid}" "${turn_a_pid}" "${relay_pid}"; do
    [[ -n "${pid}" ]] && kill -KILL "${pid}" 2>/dev/null
  done
  if [[ -n "${kept_work_dir}" ]]; then
    printf 'M9_BENCH artifacts kept at %s\n' "${kept_work_dir}"
  elif [[ -z "${HEYAKI_BENCH_WORK_DIR:-}" ]]; then
    rm -rf "${work_dir}"
  fi
}
trap cleanup EXIT

log() { printf 'M9_BENCH %s\n' "$*"; }

fail() {
  printf 'M9_BENCH_FAIL %s\n' "$*" >&2
  kept_work_dir="${work_dir}"
  printf '== relay.log (tail) ==\n'; tail -n 30 "${work_dir}/relay.log" 2>/dev/null || true
  for participant_log in "${work_dir}"/phase-*/*.log; do
    [[ -e "${participant_log}" ]] || continue
    printf '== %s (tail) ==\n' "${participant_log}"
    tail -n 15 "${participant_log}" 2>/dev/null || true
  done
  printf '== relay metrics (last scrape) ==\n'
  cat "${work_dir}/relay-metrics-now.txt" 2>/dev/null || true
  exit 1
}

wait_log() { # file marker timeout_seconds
  local file=$1 marker=$2 timeout_seconds=$3
  for _ in $(seq 1 $((timeout_seconds * 10))); do
    if grep -q -- "${marker}" "${file}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_proc_exit() { # pid timeout_seconds
  local pid=$1 timeout_seconds=$2
  for _ in $(seq 1 $((timeout_seconds * 10))); do
    kill -0 "${pid}" 2>/dev/null || return 0
    sleep 0.1
  done
  return 1
}

proc_rss() { # pid -> VmRSS in KB (0 when unreadable)
  local value=""
  value=$(sed -n 's/^VmRSS:[[:space:]]*\([0-9]*\).*/\1/p' \
    "/proc/$1/status" 2>/dev/null || true)
  printf '%s' "${value:-0}"
}

proc_fds() { # pid -> open fd count (0 when unreadable)
  local value=""
  value=$(find "/proc/$1/fd" -mindepth 1 -maxdepth 1 -printf '.' 2>/dev/null | wc -c || true)
  printf '%s' "${value:-0}"
}

relay_scrape() { # url ca outfile
  python3 - "$1" "$2" "$3" <<'PY'
import socket, ssl, sys
url, ca, out = sys.argv[1], sys.argv[2], sys.argv[3]
host, port = url.removeprefix("wss://").rsplit(":", 1)
ctx = ssl.create_default_context(cafile=ca)
with socket.create_connection((host, int(port)), timeout=10) as sock:
    with ctx.wrap_socket(sock, server_hostname=host) as tls:
        tls.sendall(b"GET /metrics HTTP/1.0\r\nHost: heyaki-relay\r\n\r\n")
        body = b""
        while True:
            chunk = tls.recv(65536)
            if not chunk:
                break
            body += chunk
text = body.decode("utf-8", "replace")
head, _, payload = text.partition("\r\n\r\n")
status = head.split("\r\n", 1)[0]
if " 200 " not in status:
    sys.stderr.write("metrics scrape not 200: " + status + "\n")
    sys.exit(1)
lines = []
for line in payload.splitlines():
    if not line or line.startswith("#"):
        continue
    parts = line.rsplit(" ", 1)
    if len(parts) == 2:
        lines.append(parts[0].split("{", 1)[0] + " " + parts[1])
with open(out, "w") as handle:
    handle.write("\n".join(lines) + "\n")
PY
}

metric_of() { # scrape-file family -> value
  awk -v fam="$2" '$1 == fam { print $2; exit }' "$1"
}

pick_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
PY
}

percentile() { # file percentile(0-100) -> value at nearest-rank index
  sort -n "$1" | awk -v p="$2" '
    { a[NR] = $1 }
    END {
      if (NR == 0) { print 0; exit }
      idx = int(p / 100 * (NR - 1) + 0.5)
      if (idx < 0) idx = 0
      if (idx >= NR) idx = NR - 1
      print a[idx + 1]
    }'
}

field_of() { # "k1=v1 k2=v2" field -> v
  printf '%s\n' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -1
}

# Wait until the relay endpoint table drains back to zero after a pair exits
# (leases expire on their own once heartbeats stop).
wait_endpoint_drain() { # timeout_seconds
  local timeout_seconds=$1
  for _ in $(seq 1 $((timeout_seconds * 2))); do
    relay_scrape "${relay_url}" "${work_dir}/ca.pem" \
      "${work_dir}/relay-metrics-now.txt" || fail "relay scrape during drain failed"
    local entries=""
    entries=$(metric_of "${work_dir}/relay-metrics-now.txt" \
      heyaki_relay_endpoint_table_entries)
    [[ "${entries}" == "0" ]] && return 0
    sleep 0.5
  done
  return 1
}

# ---- shared relay material ---------------------------------------------------
issue_certificate() { # prefix
  local prefix=$1
  openssl req -newkey rsa:2048 -nodes \
    -subj "/CN=127.0.0.1" \
    -keyout "${work_dir}/${prefix}-key.pem" -out "${work_dir}/${prefix}.csr" \
    >/dev/null 2>&1
  openssl x509 -req -in "${work_dir}/${prefix}.csr" -CA "${work_dir}/ca.pem" \
    -CAkey "${work_dir}/ca-key.pem" -CAcreateserial -days 1 \
    -extfile "${work_dir}/san.ext" \
    -out "${work_dir}/${prefix}-cert.pem" >/dev/null 2>&1
}

# python's TLS stack rejects a self-signed CA without basicConstraints/keyUsage
# when scraping /metrics (same finding as the soak harness).
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -set_serial 1 \
  -subj "/CN=heyaki-relay-test" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "${work_dir}/ca-key.pem" -out "${work_dir}/ca.pem" >/dev/null 2>&1
printf 'subjectAltName=IP:127.0.0.1\n' >"${work_dir}/san.ext"
issue_certificate relay

tenant="tenant-a"
token="TEST-ONLY-m9-bench-token-0123456789abcdef"
expiry=$(python3 - <<'PY'
import time
print(int(time.time() * 1000) + 7 * 24 * 3600 * 1000)
PY
)

relay_port=$(pick_port)
relay_url="wss://127.0.0.1:${relay_port}"
relay_db="${work_dir}/relay.sqlite"
"${demo_bin}" seed-token "${relay_db}" "${tenant}" "${token}" "${expiry}" 512

cat >"${work_dir}/relay.conf" <<RELAY_EOF
listen_address = 127.0.0.1
listen_port = ${relay_port}
tls_certificate_file = ${work_dir}/relay-cert.pem
tls_private_key_file = ${work_dir}/relay-key.pem
database_file = ${relay_db}
handshake_timeout_milliseconds = 6000
shutdown_timeout_milliseconds = 2000
RELAY_EOF

"${relay_bin}" --config "${work_dir}/relay.conf" >"${work_dir}/relay.log" 2>&1 &
relay_pid=$!
for _ in $(seq 1 50); do
  if (exec 3<>"/dev/tcp/127.0.0.1/${relay_port}") 2>/dev/null; then
    break
  fi
  sleep 0.1
done
kill -0 "${relay_pid}" 2>/dev/null || fail "relay did not start"

relay_scrape "${relay_url}" "${work_dir}/ca.pem" "${work_dir}/relay-baseline.txt" ||
  fail "baseline relay scrape failed"
relay_baseline_rss=$(proc_rss "${relay_pid}")
relay_baseline_fds=$(proc_fds "${relay_pid}")
relay_baseline_signaling=$(metric_of "${work_dir}/relay-baseline.txt" \
  heyaki_relay_signaling_forwarded_total)

# ---- enrolled pair shared by Phase R / Phase T ------------------------------
mkdir -p "${work_dir}/pair"
chmod 700 "${work_dir}/pair"
first_db="${work_dir}/pair/first.sqlite"
second_db="${work_dir}/pair/second.sqlite"
SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" init-profile "${first_db}" matrix.first \
  >"${work_dir}/pair/init-first.log" 2>&1 || fail "init-profile(first) failed"
SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" init-profile "${second_db}" matrix.second \
  >"${work_dir}/pair/init-second.log" 2>&1 || fail "init-profile(second) failed"
SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" seed-trust "${first_db}" "${second_db}" \
  >"${work_dir}/pair/seed.log" 2>&1 || fail "seed-trust failed"
SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" enroll "${first_db}" matrix.first \
  "${relay_url}" "${work_dir}/ca.pem" "${tenant}" "${token}" \
  >"${work_dir}/pair/enroll-first.log" 2>&1 || fail "enroll(first) failed"
SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" enroll "${second_db}" matrix.second \
  "${relay_url}" "${work_dir}/ca.pem" "${tenant}" "${token}" \
  >"${work_dir}/pair/enroll-second.log" 2>&1 || fail "enroll(second) failed"

# One fresh-process cycle: spawn responder, spawn bench initiator
# (connect-only), both exit on their own. Appends login_ms samples (both
# processes) and connect_ms samples (initiator) to the sample files.
run_cycle() { # phase dir label responder_extra_flags... -- initiator_extra_flags...
  local phase=$1 dir=$2 label=$3
  shift 3
  local responder_flags=()
  local initiator_flags=()
  local collecting_responder=true
  for argument in "$@"; do
    if [[ "${argument}" == "--" ]]; then
      collecting_responder=false
    elif ${collecting_responder}; then
      responder_flags+=("${argument}")
    else
      initiator_flags+=("${argument}")
    fi
  done
  local responder_log="${dir}/${label}-responder.log"
  local initiator_log="${dir}/${label}-initiator.log"
  SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" run "${second_db}" matrix.second \
    "${relay_url}" "${work_dir}/ca.pem" "${tenant}" 60000 \
    --role responder --hold-ms 5000 --authenticate-budget-ms 25000 \
    "${responder_flags[@]}" \
    >"${responder_log}" 2>&1 &
  responder_pid=$!
  wait_log "${responder_log}" "MATRIX_PHASE connecting" 20 ||
    fail "${label}: responder never reached connecting"
  SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" run "${first_db}" matrix.first \
    "${relay_url}" "${work_dir}/ca.pem" "${tenant}" 60000 \
    --role initiator --bench-initiator --bench-connect-only \
    --authenticate-budget-ms 25000 \
    "${initiator_flags[@]}" \
    >"${initiator_log}" 2>&1 &
  initiator_pid=$!
  wait_proc_exit "${initiator_pid}" 90 || fail "${label}: initiator did not exit"
  wait "${initiator_pid}" 2>/dev/null || true
  initiator_pid=""
  wait_proc_exit "${responder_pid}" 90 || fail "${label}: responder did not exit"
  wait "${responder_pid}" 2>/dev/null || true
  responder_pid=""
  # pipefail-safe: a missing marker yields no samples; the authenticated
  # gate right below turns a short sample set into a loud failure.
  { grep -h -- "relay-ready" "${responder_log}" "${initiator_log}" || true; } |
    sed -n 's/.*login_ms=\([0-9]*\).*/\1/p' >>"${work_dir}/login-ms.txt"
  { grep -h -- "BENCH_CONNECT" "${initiator_log}" || true; } |
    sed -n 's/.*duration_ms=\([0-9]*\).*/\1/p' >>"${work_dir}/connect-${phase}-ms.txt"
  { grep -h -- "BENCH_CONNECT" "${initiator_log}" || true; } |
    sed -n 's/.*data_path=\([a-z_]*\).*/\1/p' >>"${work_dir}/path-${phase}.txt"
  grep -q "MATRIX_RESULT authenticated=1" "${initiator_log}" ||
    fail "${label}: initiator never authenticated (see ${initiator_log})"
}

# ---- Phase R: registration + direct connect P95 ------------------------------
log "PHASE_R begin cycles=${cycles}"
mkdir -p "${work_dir}/phase-r"
chmod 700 "${work_dir}/phase-r"
: >"${work_dir}/login-ms.txt"
: >"${work_dir}/connect-r-ms.txt"
: >"${work_dir}/path-r.txt"
for cycle in $(seq 1 "${cycles}"); do
  run_cycle r "${work_dir}/phase-r" "cycle${cycle}"
  wait_endpoint_drain 15 ||
    fail "cycle ${cycle}: relay endpoint table did not drain between iterations"
done

login_p95=$(percentile "${work_dir}/login-ms.txt" 95)
connect_r_p95=$(percentile "${work_dir}/connect-r-ms.txt" 95)
log "PHASE_R samples=$(wc -l <"${work_dir}/login-ms.txt") login_p95_ms=${login_p95} connect_p95_ms=${connect_r_p95}"
(( login_p95 <= login_p95_ms )) ||
  fail "registration P95 ${login_p95}ms exceeds ${login_p95_ms}ms gate"
(( connect_r_p95 <= connect_p95_ms )) ||
  fail "direct connect P95 ${connect_r_p95}ms exceeds ${connect_p95_ms}ms gate"
if grep -qv "^direct_host$" "${work_dir}/path-r.txt"; then
  fail "Phase R saw a non-direct data path: $(sort -u "${work_dir}/path-r.txt" | tr '\n' ' ')"
fi

# ---- Phase T: TURN fallback P95 ----------------------------------------------
log "PHASE_T begin cycles=${cycles}"
turn_a_port=$(pick_port)
turn_b_port=$(pick_port)
turn_username="benchturn"
turn_credential="TEST-ONLY-bench-turn-secret"
# M9-19: the TURN address must be a non-loopback host address. The libnice ICE
# backend binds its TURN relay sockets to physical interface addresses and
# sets IP_UNICAST_IF, so packets destined for 127.0.0.1 are silently dropped by
# the kernel (sendmsg succeeds, nothing is delivered) — a loopback-only TURN
# server is a physically unreachable topology for libnice. The libjuice client
# backend does not set the option and works with either address.
turn_host=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
if [[ -z "${turn_host}" || "${turn_host}" == 127.* ]]; then
  fail "no non-loopback host address found for the TURN servers (libnice cannot reach a loopback TURN server)"
fi
"${turn_bin}" --port "${turn_a_port}" --bind 0.0.0.0 --external "${turn_host}" \
  --username "${turn_username}" \
  --credential "${turn_credential}" --relay-port-begin 49200 --relay-port-end 49249 \
  >"${work_dir}/turn-a.log" 2>&1 &
turn_a_pid=$!
"${turn_bin}" --port "${turn_b_port}" --bind 0.0.0.0 --external "${turn_host}" \
  --username "${turn_username}" \
  --credential "${turn_credential}" --relay-port-begin 49250 --relay-port-end 49299 \
  >"${work_dir}/turn-b.log" 2>&1 &
turn_b_pid=$!
wait_log "${work_dir}/turn-a.log" "TURN_SERVER_READY" 15 || fail "turn server A did not start"
wait_log "${work_dir}/turn-b.log" "TURN_SERVER_READY" 15 || fail "turn server B did not start"

mkdir -p "${work_dir}/phase-t"
chmod 700 "${work_dir}/phase-t"
: >"${work_dir}/connect-t-ms.txt"
: >"${work_dir}/path-t.txt"
for cycle in $(seq 1 "${cycles}"); do
  run_cycle t "${work_dir}/phase-t" "cycle${cycle}" \
    --turn "${turn_host}:${turn_b_port}" --turn-username "${turn_username}" \
    --turn-credential "${turn_credential}" --force-turn -- \
    --turn "${turn_host}:${turn_a_port}" --turn-username "${turn_username}" \
    --turn-credential "${turn_credential}" --force-turn
  wait_endpoint_drain 15 ||
    fail "turn cycle ${cycle}: relay endpoint table did not drain between iterations"
done

connect_t_p95=$(percentile "${work_dir}/connect-t-ms.txt" 95)
log "PHASE_T samples=$(wc -l <"${work_dir}/connect-t-ms.txt") connect_p95_ms=${connect_t_p95}"
(( connect_t_p95 <= turn_p95_ms )) ||
  fail "TURN fallback P95 ${connect_t_p95}ms exceeds ${turn_p95_ms}ms gate"
# Same contract as the Windows matrix turn_udp scenario: with forced TURN on
# a single host, the nominated pair can be local-srflx x peer-relayed (half
# relayed); the label carries the local candidate type. M9-19: with the TURN
# server on a non-loopback host address (required for libnice), the libjuice
# client also nominates local-host x peer-relayed pairs (direct_host) — the
# peer under forced TURN only issues relayed candidates, so the data still
# rides the peer's TURN server. All three labels mean a TURN allocation
# mediated the path.
if grep -qv -E "^(turn_udp|direct_srflx|direct_host)$" "${work_dir}/path-t.txt"; then
  fail "Phase T saw a non-TURN data path: $(sort -u "${work_dir}/path-t.txt" | tr '\n' ' ')"
fi

kill -TERM "${turn_a_pid}" "${turn_b_pid}" 2>/dev/null || true
wait_proc_exit "${turn_a_pid}" 10 || kill -KILL "${turn_a_pid}" 2>/dev/null || true
wait_proc_exit "${turn_b_pid}" 10 || kill -KILL "${turn_b_pid}" 2>/dev/null || true
turn_a_pid=""
turn_b_pid=""

# ---- Phase L: long-lived suite ------------------------------------------------
log "PHASE_L begin subscribers=${subscribers}"
mkdir -p "${work_dir}/phase-l"
chmod 700 "${work_dir}/phase-l"

# Subscriber profiles: fresh identities, enrolled and mutually trusted with
# the initiator profile (matrix.first). The bench initiator dials every
# discovered peer, so each subscriber is a fan-out receiver.
for index in $(seq 1 "${subscribers}"); do
  sub_db="${work_dir}/phase-l/sub-${index}.sqlite"
  SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" init-profile "${sub_db}" matrix.sub \
    >"${work_dir}/phase-l/init-sub-${index}.log" 2>&1 || fail "sub init #${index} failed"
  SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" seed-trust "${first_db}" "${sub_db}" \
    "$((10 + 2 * index))" \
    >"${work_dir}/phase-l/seed-sub-${index}.log" 2>&1 || fail "sub seed #${index} failed"
  SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" enroll "${sub_db}" matrix.sub \
    "${relay_url}" "${work_dir}/ca.pem" "${tenant}" "${token}" \
    >"${work_dir}/phase-l/enroll-sub-${index}.log" 2>&1 || fail "sub enroll #${index} failed"
done
for index in $(seq 1 "${subscribers}"); do
  sub_log="${work_dir}/phase-l/sub-${index}.log"
  SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" run \
    "${work_dir}/phase-l/sub-${index}.sqlite" matrix.sub \
    "${relay_url}" "${work_dir}/ca.pem" "${tenant}" 300000 \
    --role responder --bench-responder --bench-shell --hold-ms 240000 \
    --authenticate-budget-ms 25000 \
    >"${sub_log}" 2>&1 &
  responder_pids+=("$!")
done
for index in $(seq 1 "${subscribers}"); do
  wait_log "${work_dir}/phase-l/sub-${index}.log" "MATRIX_PHASE connecting" 20 ||
    fail "subscriber #${index} never reached connecting"
done

initiator_log="${work_dir}/phase-l/initiator.log"
SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" run "${first_db}" matrix.first \
  "${relay_url}" "${work_dir}/ca.pem" "${tenant}" 300000 \
  --role initiator --bench-initiator --bench-shell \
  --bench-peers "${subscribers}" \
  --bench-msg-n "${msg_n}" --bench-rpc-n "${rpc_n}" \
  --bench-rpc-concurrent-n "${rpc_conc_n}" --bench-fanout-n "${fanout_n}" \
  --bench-file-bytes "${file_bytes}" --bench-file-multi-bytes "${file_multi_bytes}" \
  --authenticate-budget-ms 25000 \
  >"${initiator_log}" 2>&1 &
initiator_pid=$!
wait_proc_exit "${initiator_pid}" 300 || fail "Phase L initiator did not exit"
wait "${initiator_pid}" 2>/dev/null || true
initiator_pid=""

grep -q "BENCH_SUMMARY ok=1" "${initiator_log}" ||
  fail "Phase L bench suite did not complete: $(tail -n 3 "${initiator_log}" | tr '\n' ' ')"
bench_summary=$(sed -n 's/^BENCH_SUMMARY //p' "${initiator_log}" | tail -1)
log "PHASE_L summary: ${bench_summary}"
bench_connect_peers=$(sed -n 's/^BENCH_CONNECT .* peers=\([0-9]*\).*/\1/p' "${initiator_log}" | tail -1)
[[ "${bench_connect_peers}" == "${subscribers}" ]] ||
  fail "Phase L authenticated ${bench_connect_peers} of ${subscribers} subscribers"

message_metric=$(sed -n 's/^BENCH_METRIC name=message_rtt //p' "${initiator_log}" | tail -1)
rpc_metric=$(sed -n 's/^BENCH_METRIC name=rpc_latency //p' "${initiator_log}" | tail -1)
rpc_conc_metric=$(sed -n 's/^BENCH_METRIC name=rpc_concurrent_latency //p' "${initiator_log}" | tail -1)
fanout_metric=$(sed -n 's/^BENCH_METRIC name=fanout_publish //p' "${initiator_log}" | tail -1)
file_single=$(sed -n 's/^BENCH_THROUGHPUT name=file_single //p' "${initiator_log}" | tail -1)
file_multi=$(sed -n 's/^BENCH_THROUGHPUT name=file_multi_concurrent //p' "${initiator_log}" | tail -1)
file_shell=$(sed -n 's/^BENCH_THROUGHPUT name=file_under_shell //p' "${initiator_log}" | tail -1)
shell_idle=$(sed -n 's/^BENCH_METRIC name=shell_ping_idle //p' "${initiator_log}" | tail -1)
shell_busy=$(sed -n 's/^BENCH_METRIC name=shell_ping_contended //p' "${initiator_log}" | tail -1)

[[ "$(field_of "${message_metric}" failures)" == "0" ]] ||
  fail "message section had failures: ${message_metric}"
(( $(field_of "${message_metric}" p95_us) <= msg_p95_ms * 1000 )) ||
  fail "message P95 $(field_of "${message_metric}" p95_us)us exceeds ${msg_p95_ms}ms sanity gate"
[[ "$(field_of "${rpc_metric}" failures)" == "0" ]] ||
  fail "sequential RPC section had failures: ${rpc_metric}"
(( $(field_of "${rpc_metric}" p95_us) <= msg_p95_ms * 1000 )) ||
  fail "rpc P95 $(field_of "${rpc_metric}" p95_us)us exceeds ${msg_p95_ms}ms sanity gate"
[[ "$(field_of "${rpc_conc_metric}" failures)" == "0" ]] ||
  fail "concurrent RPC section had failures: ${rpc_conc_metric}"
[[ "$(field_of "${rpc_metric}" n)" == "${rpc_n}" ]] ||
  fail "sequential RPC completed $(field_of "${rpc_metric}" n)/${rpc_n}"
[[ "$(field_of "${fanout_metric}" publish_failures)" == "0" ]] ||
  fail "fan-out publishes failed: ${fanout_metric}"
[[ "$(field_of "${file_single}" ok)" == "1" ]] || fail "single file push failed: ${file_single}"
[[ "$(field_of "${file_multi}" ok)" == "1" ]] || fail "concurrent file push failed: ${file_multi}"
[[ "$(field_of "${file_shell}" ok)" == "1" ]] || fail "under-shell file push failed: ${file_shell}"
[[ "$(field_of "${shell_idle}" failures)" == "0" ]] ||
  fail "idle shell pings incomplete: ${shell_idle}"
[[ "$(field_of "${shell_busy}" failures)" == "0" ]] ||
  fail "contended shell pings incomplete: ${shell_busy}"

# Fan-out delivery per subscriber: every sequence delivered exactly once.
for index in $(seq 1 "${subscribers}"); do
  sub_log="${work_dir}/phase-l/sub-${index}.log"
  delivered=$(grep -c -- "BENCH_FANOUT_RX" "${sub_log}" || true)
  # pipefail-safe: zero deliveries surface through the delivered gate, not
  # through a dead pipeline.
  unique=$({ grep -- "BENCH_FANOUT_RX" "${sub_log}" || true; } |
    sed -n 's/.*seq=\([0-9]*\).*/\1/p' | sort -nu | wc -l)
  fanout_p95_us=$({ grep -- "BENCH_FANOUT_RX" "${sub_log}" || true; } |
    sed -n 's/.*rtt_us=\([0-9]*\).*/\1/p' | percentile /dev/stdin 95)
  (( delivered == fanout_n && unique == fanout_n )) ||
    fail "subscriber #${index} fan-out delivered ${delivered} (unique ${unique}) of ${fanout_n}"
  log "PHASE_L fanout sub=${index} delivered=${delivered} p95_us=${fanout_p95_us}"
  (( fanout_p95_us <= msg_p95_ms * 1000 )) ||
    fail "subscriber #${index} fan-out P95 ${fanout_p95_us}us exceeds sanity gate"
done

for pid in "${responder_pids[@]}"; do
  kill -TERM "${pid}" 2>/dev/null || true
done
for pid in "${responder_pids[@]}"; do
  wait_proc_exit "${pid}" 30 || kill -KILL "${pid}" 2>/dev/null || true
done
responder_pids=()

# ---- relay footprint ----------------------------------------------------------
wait_endpoint_drain 20 || fail "relay endpoint table did not drain after Phase L"
relay_scrape "${relay_url}" "${work_dir}/ca.pem" "${work_dir}/relay-final.txt" ||
  fail "final relay scrape failed"
relay_final_rss=$(proc_rss "${relay_pid}")
relay_final_fds=$(proc_fds "${relay_pid}")
relay_final_signaling=$(metric_of "${work_dir}/relay-final.txt" \
  heyaki_relay_signaling_forwarded_total)
for family in heyaki_relay_endpoint_table_entries heyaki_relay_lease_entries; do
  value=$(metric_of "${work_dir}/relay-final.txt" "$family")
  [[ "${value}" == "0" ]] || fail "relay ${family}=${value} after drain"
done
(( relay_final_rss <= relay_baseline_rss + 65536 )) ||
  fail "relay rss growth ${relay_baseline_rss}->${relay_final_rss} KB exceeds 64MiB gate"
(( relay_final_fds <= relay_baseline_fds + 64 )) ||
  fail "relay fd growth ${relay_baseline_fds}->${relay_final_fds} exceeds gate"

kill -TERM "${relay_pid}" 2>/dev/null || true
wait_proc_exit "${relay_pid}" 15 || kill -KILL "${relay_pid}" 2>/dev/null || true
wait "${relay_pid}" 2>/dev/null || true
relay_pid=""

log "OK login_p95_ms=${login_p95} connect_p95_ms=${connect_r_p95} turn_p95_ms=${connect_t_p95}"
printf 'M9_BENCH_OK login_p95_ms=%s connect_p95_ms=%s turn_p95_ms=%s message_p95_us=%s rpc_p95_us=%s rpc_concurrent_p95_us=%s fanout_events=%s file_single_mib_per_s=%s file_multi_mib_per_s=%s shell_idle_p95_us=%s shell_contended_p95_us=%s relay_signaling_forwarded=%s relay_rss_kb=%s\n' \
  "${login_p95}" "${connect_r_p95}" "${connect_t_p95}" \
  "$(field_of "${bench_summary}" message_p95_us)" \
  "$(field_of "${bench_summary}" rpc_p95_us)" \
  "$(field_of "${bench_summary}" rpc_concurrent_p95_us)" \
  "${fanout_n}" \
  "$(field_of "${file_single}" mib_per_s)" \
  "$(field_of "${file_multi}" mib_per_s)" \
  "$(field_of "${shell_idle}" p95_us)" \
  "$(field_of "${shell_busy}" p95_us)" \
  "$((relay_final_signaling - relay_baseline_signaling))" \
  "${relay_final_rss}"
