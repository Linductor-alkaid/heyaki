#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

# M9-09 soak harness (loopback relay, no root, no coturn):
#
#   Phase A  session churn — one long-lived initiator cycles
#            dial/authenticate/m6+m7/disconnect in a single process while the
#            harness SIGKILLs and respawns the responder after every cycle.
#            Gates: every cycle's work completes and its session reaches a
#            terminal state (SOAK_SUMMARY work_done/closed_ok/sessions_final),
#            initiator RSS growth, fd delta, replay-guard peak, executor
#            task gauges (SOAK_CYCLE samples).
#   Phase B  discovery churn — K short-lived distinct devices enroll, log in,
#            publish an endpoint and exit against the same long-lived relay.
#            Gates: relay /metrics gauges (active sessions, endpoint table,
#            lease table, challenge tables) and relay RSS/fd stay bounded at
#            every sample.
#   Phase C  capacity overload — a second relay with tight limits
#            (max_connections=3, endpoint_directory_capacity=2) is driven by
#            concurrent participants. Gates: rejection counters fire, the
#            relay stays healthy, survivors still complete, and the relay
#            drains to zero sessions/endpoints/leases afterwards.
#
# The CI slice scales with the env knobs below. 24/72h runs scale the same
# knobs (see docs/operations/runbook.md "长稳（soak）测试"):
#   HEYAKI_SOAK_SESSION_CYCLES   (default 6)    Phase A cycles
#   HEYAKI_SOAK_CHURN_PARTICIPANTS (default 8)  Phase B distinct devices
#   HEYAKI_SOAK_OVERLOAD_PARTICIPANTS (default 5) Phase C participants
#   HEYAKI_SOAK_RSS_GROWTH_KB    (default 32768) first→last RSS growth gate
#   HEYAKI_SOAK_FD_SLACK         (default 24)   first→last fd delta gate
#
# Gated like the Windows network matrix: SKIP 77 unless
# HEYAKI_REQUIRE_M9_SOAK=1 so default local/CI ctest suites and sanitizer
# presets stay fast.

[[ "${HEYAKI_REQUIRE_M9_SOAK:-0}" == "1" ]] || {
  printf 'SKIP: set HEYAKI_REQUIRE_M9_SOAK=1 to run the M9 soak harness\n'
  exit 77
}
[[ "$(uname -s)" == "Linux" ]] || { printf 'SKIP: Linux-only soak harness\n'; exit 77; }

relay_bin=${HEYAKI_RELAY_BIN:-}
matrix_bin=${HEYAKI_MATRIX_BIN:-}
demo_bin=${HEYAKI_DEMO_BIN:-}
work_dir=${HEYAKI_SOAK_WORK_DIR:-}

usage() {
  cat <<USAGE_EOF
Usage: $0 --relay-bin PATH --matrix-bin PATH --demo-bin PATH [--work-dir PATH]
USAGE_EOF
}

while (($# > 0)); do
  case "$1" in
    --relay-bin) relay_bin=${2:?missing relay-bin value}; shift 2;;
    --matrix-bin) matrix_bin=${2:?missing matrix-bin value}; shift 2;;
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
for binary in "${relay_bin}" "${matrix_bin}" "${demo_bin}"; do
  [[ -n "${binary}" && -x "${binary}" ]] || {
    printf 'SKIP: required binary unavailable (%s)\n' "${binary}"
    exit 77
  }
done

session_cycles=${HEYAKI_SOAK_SESSION_CYCLES:-6}
churn_participants=${HEYAKI_SOAK_CHURN_PARTICIPANTS:-8}
overload_participants=${HEYAKI_SOAK_OVERLOAD_PARTICIPANTS:-5}
rss_growth_kb=${HEYAKI_SOAK_RSS_GROWTH_KB:-32768}
fd_slack=${HEYAKI_SOAK_FD_SLACK:-24}

kept_work_dir=""
if [[ -n "${work_dir}" ]]; then
  mkdir -p "${work_dir}"
else
  work_dir=$(mktemp -d /tmp/heyaki-m9-soak.XXXXXX)
fi
chmod 700 "${work_dir}"

relay_pid=""
overload_relay_pid=""
initiator_pid=""
responder_pid=""
declare -a participant_pids=()

cleanup() {
  set +e
  local pid=""
  for pid in "${participant_pids[@]:-}" "${responder_pid}" \
             "${initiator_pid}" "${overload_relay_pid}" "${relay_pid}"; do
    [[ -n "${pid}" ]] && kill -TERM "${pid}" 2>/dev/null
  done
  sleep 0.3
  for pid in "${participant_pids[@]:-}" "${responder_pid}" \
             "${initiator_pid}" "${overload_relay_pid}" "${relay_pid}"; do
    [[ -n "${pid}" ]] && kill -KILL "${pid}" 2>/dev/null
  done
  if [[ -n "${kept_work_dir}" ]]; then
    printf 'M9_SOAK artifacts kept at %s\n' "${kept_work_dir}"
  elif [[ -z "${HEYAKI_SOAK_WORK_DIR:-}" ]]; then
    rm -rf "${work_dir}"
  fi
}
trap cleanup EXIT

log() { printf 'M9_SOAK %s\n' "$*"; }

fail() {
  printf 'M9_SOAK_FAIL %s\n' "$*" >&2
  kept_work_dir="${work_dir}"
  printf '== relay.log (tail) ==\n'; tail -n 30 "${work_dir}/relay.log" 2>/dev/null || true
  printf '== relay2.log (tail) ==\n'; tail -n 30 "${work_dir}/relay2.log" 2>/dev/null || true
  printf '== initiator.log (tail) ==\n'; tail -n 40 "${work_dir}/initiator.log" 2>/dev/null || true
  for responder_log in "${work_dir}"/responder-*.log; do
    [[ -e "${responder_log}" ]] || continue
    printf '== %s (tail) ==\n' "${responder_log}"
    tail -n 12 "${responder_log}" 2>/dev/null || true
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

# One TLS scrape of /metrics; normalizes "family value" lines (label sets are
# stripped) into $3 for the metric_of reader. HTTP/1.0 keeps the response
# body a plain read-to-EOF stream.
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

sample_relay() { # tag pid url ca scrape_file
  local tag=$1 pid=$2 url=$3 ca=$4 scrape_file=$5
  relay_scrape "$url" "$ca" "$scrape_file" || fail "relay /metrics scrape failed (${tag})"
  local field_name=""
  for field_name in heyaki_relay_active_sessions heyaki_relay_endpoint_table_entries \
      heyaki_relay_lease_entries heyaki_relay_login_challenge_table_entries \
      heyaki_relay_enrollment_challenge_table_entries heyaki_relay_capacity_rejected_total \
      heyaki_relay_endpoints_capacity_rejected_total \
      heyaki_relay_endpoint_table_capacity_rejected_total; do
    [[ -n "$(metric_of "$scrape_file" "$field_name")" ]] ||
      fail "metric family missing from ${tag} scrape: ${field_name}"
  done
  log "SOAK_RELAY_SAMPLE tag=${tag} active_sessions=$(metric_of "$scrape_file" heyaki_relay_active_sessions) endpoint_entries=$(metric_of "$scrape_file" heyaki_relay_endpoint_table_entries) lease_entries=$(metric_of "$scrape_file" heyaki_relay_lease_entries) login_challenges=$(metric_of "$scrape_file" heyaki_relay_login_challenge_table_entries) enroll_challenges=$(metric_of "$scrape_file" heyaki_relay_enrollment_challenge_table_entries) capacity_rejected=$(metric_of "$scrape_file" heyaki_relay_capacity_rejected_total) endpoints_capacity_rejected=$(metric_of "$scrape_file" heyaki_relay_endpoints_capacity_rejected_total) endpoint_table_capacity_rejected=$(metric_of "$scrape_file" heyaki_relay_endpoint_table_capacity_rejected_total) relay_rss_kb=$(proc_rss "$pid") relay_fds=$(proc_fds "$pid")"
}

field_of() { # "k1=v1 k2=v2" field -> v
  printf '%s\n' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -1
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

# ---- shared relay material -------------------------------------------------
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

# The CA carries explicit CA extensions: python's TLS stack (unlike the C++
# client defaults) rejects a self-signed CA without basicConstraints/keyUsage
# when scraping /metrics.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -set_serial 1 \
  -subj "/CN=heyaki-relay-test" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "${work_dir}/ca-key.pem" -out "${work_dir}/ca.pem" >/dev/null 2>&1
printf 'subjectAltName=IP:127.0.0.1\n' >"${work_dir}/san.ext"
issue_certificate relay
issue_certificate relay2

tenant="tenant-a"
token="TEST-ONLY-m9-soak-token-0123456789abcdef"
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

relay_baseline="${work_dir}/relay-baseline.txt"
sample_relay baseline "${relay_pid}" "${relay_url}" "${work_dir}/ca.pem" \
  "${relay_baseline}"
relay_baseline_rss=$(proc_rss "${relay_pid}")
relay_baseline_fds=$(proc_fds "${relay_pid}")

# ---- Phase A: session churn (long-lived initiator, respawned responder) ----
log "PHASE_A begin session_cycles=${session_cycles}"
mkdir -p "${work_dir}/phase-a"
chmod 700 "${work_dir}/phase-a"
first_db="${work_dir}/phase-a/first.sqlite"
second_db="${work_dir}/phase-a/second.sqlite"
SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" init-profile "${first_db}" matrix.first \
  >"${work_dir}/phase-a/init-first.log" 2>&1 || fail "init-profile(first) failed"
SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" init-profile "${second_db}" matrix.second \
  >"${work_dir}/phase-a/init-second.log" 2>&1 || fail "init-profile(second) failed"
SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" seed-trust "${first_db}" "${second_db}" \
  >"${work_dir}/phase-a/seed.log" 2>&1 || fail "seed-trust failed"
SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" enroll "${first_db}" matrix.first \
  "${relay_url}" "${work_dir}/ca.pem" "${tenant}" "${token}" \
  >"${work_dir}/phase-a/enroll-first.log" 2>&1 || fail "enroll(first) failed"
SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" enroll "${second_db}" matrix.second \
  "${relay_url}" "${work_dir}/ca.pem" "${tenant}" "${token}" \
  >"${work_dir}/phase-a/enroll-second.log" 2>&1 || fail "enroll(second) failed"

responder_log="${work_dir}/responder-0.log"
SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" run "${second_db}" matrix.second \
  "${relay_url}" "${work_dir}/ca.pem" "${tenant}" 300000 \
  --role responder --hold-ms 300000 --authenticate-budget-ms 25000 \
  >"${responder_log}" 2>&1 &
responder_pid=$!
wait_log "${responder_log}" "MATRIX_PHASE connecting" 20 ||
  fail "responder generation 0 did not reach connecting"

initiator_log="${work_dir}/initiator.log"
SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" run "${first_db}" matrix.first \
  "${relay_url}" "${work_dir}/ca.pem" "${tenant}" 600000 \
  --role initiator --soak-cycles "${session_cycles}" \
  --connect-retries 2 --authenticate-budget-ms 25000 \
  >"${initiator_log}" 2>&1 &
initiator_pid=$!

for cycle in $(seq 1 "${session_cycles}"); do
  wait_log "${initiator_log}" "SOAK_CYCLE idx=${cycle} state=work-done" 120 ||
    fail "session cycle ${cycle} never reached work-done"
  # Unclean peer death: the authenticated session must reach a terminal state
  # without any close handshake.
  kill -KILL "${responder_pid}" 2>/dev/null || true
  wait "${responder_pid}" 2>/dev/null || true
  responder_pid=""
  sample_relay "phase-a-cycle-${cycle}-killed" "${relay_pid}" "${relay_url}" \
    "${work_dir}/ca.pem" "${work_dir}/relay-metrics-now.txt"
  wait_log "${initiator_log}" "SOAK_CYCLE idx=${cycle} state=closed" 60 ||
    fail "session cycle ${cycle} never closed after responder SIGKILL"
  if (( cycle == session_cycles )); then
    break
  fi
  responder_log="${work_dir}/responder-${cycle}.log"
  SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" run "${second_db}" matrix.second \
    "${relay_url}" "${work_dir}/ca.pem" "${tenant}" 300000 \
    --role responder --hold-ms 300000 --authenticate-budget-ms 25000 \
    >"${responder_log}" 2>&1 &
  responder_pid=$!
  wait_log "${responder_log}" "MATRIX_PHASE connecting" 20 ||
    fail "responder generation ${cycle} did not reach connecting"
  sample_relay "phase-a-cycle-${cycle}-respawned" "${relay_pid}" "${relay_url}" \
    "${work_dir}/ca.pem" "${work_dir}/relay-metrics-now.txt"
done

wait_proc_exit "${initiator_pid}" 90 || fail "initiator did not exit after the soak summary"
wait "${initiator_pid}" 2>/dev/null || true
initiator_pid=""

summary=$(sed -n 's/^SOAK_SUMMARY //p' "${initiator_log}" | tail -1)
[[ -n "${summary}" ]] || fail "initiator produced no SOAK_SUMMARY"
result=$(sed -n 's/^MATRIX_RESULT //p' "${initiator_log}" | tail -1)
log "PHASE_A summary: ${summary}"
log "PHASE_A result: ${result}"

require_field() { # value name
  [[ -n "$1" ]] || fail "SOAK_SUMMARY field missing: $2"
}

# The summary's cycles field is "completed/requested".
summary_cycles=$(field_of "${summary}" cycles)
summary_cycles=${summary_cycles%%/*}
summary_work_done=$(field_of "${summary}" work_done)
summary_closed_ok=$(field_of "${summary}" closed_ok)
summary_rss_first=$(field_of "${summary}" rss_first_kb)
summary_rss_last=$(field_of "${summary}" rss_last_kb)
summary_rss_max=$(field_of "${summary}" rss_max_kb)
summary_fds_first=$(field_of "${summary}" fds_first)
summary_fds_last=$(field_of "${summary}" fds_last)
summary_fds_max=$(field_of "${summary}" fds_max)
summary_replay_peak=$(field_of "${summary}" replay_peak)
summary_sessions_final=$(field_of "${summary}" sessions_final)
summary_sessions_live=$(field_of "${summary}" sessions_live_final)
summary_tasks_final=$(field_of "${summary}" tasks_active_final)
require_field "${summary_cycles}" cycles
require_field "${summary_work_done}" work_done
require_field "${summary_closed_ok}" closed_ok
require_field "${summary_rss_first}" rss_first_kb
require_field "${summary_rss_last}" rss_last_kb
require_field "${summary_rss_max}" rss_max_kb
require_field "${summary_fds_first}" fds_first
require_field "${summary_fds_last}" fds_last
require_field "${summary_fds_max}" fds_max
require_field "${summary_replay_peak}" replay_peak
require_field "${summary_sessions_final}" sessions_final
require_field "${summary_sessions_live}" sessions_live_final
require_field "${summary_tasks_final}" tasks_active_final

[[ "${summary_cycles}" == "${session_cycles}" ]] ||
  fail "soak completed ${summary_cycles}/${session_cycles} cycles"
[[ "${summary_work_done}" == "${session_cycles}" ]] ||
  fail "soak work_done=${summary_work_done}/${session_cycles}"
[[ "${summary_closed_ok}" == "${session_cycles}" ]] ||
  fail "soak closed_ok=${summary_closed_ok}/${session_cycles}"
# Closed sessions retire into the node's bounded diagnostic history by
# design, so the strict gate is "no live session remains"; the total listing
# (history included) must still track the cycle count within a small retry
# allowance instead of growing without bound.
[[ "${summary_sessions_live}" == "0" ]] ||
  fail "live initiator sessions did not drain: ${summary_sessions_live}"
(( summary_sessions_final <= session_cycles * 4 + 16 )) ||
  fail "initiator session listing ${summary_sessions_final} grew past the bounded-history allowance for ${session_cycles} cycles"
[[ "${summary_tasks_final}" == "0" ]] ||
  fail "executor active tasks did not drain: ${summary_tasks_final}"
(( summary_fds_last <= summary_fds_first + fd_slack )) ||
  fail "initiator fd growth ${summary_fds_first}->${summary_fds_last} exceeds slack ${fd_slack}"
(( summary_rss_last <= summary_rss_first + rss_growth_kb )) ||
  fail "initiator rss growth ${summary_rss_first}->${summary_rss_last} KB exceeds ${rss_growth_kb} KB"
(( summary_rss_max <= summary_rss_first + 4 * rss_growth_kb )) ||
  fail "initiator rss peak ${summary_rss_max} KB exceeds 4x growth gate"
# Replay-guard boundedness: the default per-peer policy capacity is 256
# entries; one peer cycling signaling objects must stay well under it.
(( summary_replay_peak <= 256 )) ||
  fail "replay guard peak ${summary_replay_peak} exceeds the per-peer bound"
[[ "$(field_of "${result}" authenticated)" == "1" ]] ||
  fail "soak MATRIX_RESULT authenticated != 1"
[[ "$(field_of "${result}" m7_file)" == "1" ]] ||
  fail "soak MATRIX_RESULT m7_file != 1"

# ---- Phase B: distinct-device discovery churn ------------------------------
log "PHASE_B begin churn_participants=${churn_participants}"
mkdir -p "${work_dir}/phase-b"
chmod 700 "${work_dir}/phase-b"
for index in $(seq 1 "${churn_participants}"); do
  churn_db="${work_dir}/phase-b/churn-${index}.sqlite"
  SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" init-profile "${churn_db}" matrix.churn \
    >"${work_dir}/phase-b/init-${index}.log" 2>&1 || fail "churn init-profile #${index} failed"
  SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" enroll "${churn_db}" matrix.churn \
    "${relay_url}" "${work_dir}/ca.pem" "${tenant}" "${token}" \
    >"${work_dir}/phase-b/enroll-${index}.log" 2>&1 || fail "churn enroll #${index} failed"
  SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" run "${churn_db}" matrix.churn \
    "${relay_url}" "${work_dir}/ca.pem" "${tenant}" 20000 \
    --role responder --hold-ms 300 --authenticate-budget-ms 1500 \
    >"${work_dir}/phase-b/run-${index}.log" 2>&1 || true
  sample_relay "phase-b-${index}" "${relay_pid}" "${relay_url}" \
    "${work_dir}/ca.pem" "${work_dir}/relay-metrics-now.txt"
done

# Long-lived relay gates across both churn phases.
sample_relay "phase-b-final" "${relay_pid}" "${relay_url}" \
  "${work_dir}/ca.pem" "${work_dir}/relay-final.txt"
relay_final_rss=$(proc_rss "${relay_pid}")
relay_final_fds=$(proc_fds "${relay_pid}")
for bound_pair in \
  "heyaki_relay_active_sessions 4" \
  "heyaki_relay_endpoint_table_entries 8" \
  "heyaki_relay_lease_entries 4" \
  "heyaki_relay_login_challenge_table_entries 8" \
  "heyaki_relay_enrollment_challenge_table_entries 8"; do
  family=${bound_pair%% *}
  bound=${bound_pair##* }
  value=$(metric_of "${work_dir}/relay-final.txt" "$family")
  (( value <= bound )) ||
    fail "relay ${family}=${value} exceeds bound ${bound} after churn"
done
(( relay_final_rss <= relay_baseline_rss + 2 * rss_growth_kb )) ||
  fail "relay rss growth ${relay_baseline_rss}->${relay_final_rss} KB exceeds gate"
(( relay_final_fds <= relay_baseline_fds + 32 )) ||
  fail "relay fd growth ${relay_baseline_fds}->${relay_final_fds} exceeds gate"

# ---- Phase C: capacity overload on a tight relay ---------------------------
log "PHASE_C begin overload_participants=${overload_participants}"
overload_port=$(pick_port)
overload_url="wss://127.0.0.1:${overload_port}"
overload_db="${work_dir}/relay2.sqlite"
"${demo_bin}" seed-token "${overload_db}" "${tenant}" "${token}" "${expiry}" 512
cat >"${work_dir}/relay2.conf" <<RELAY_EOF
listen_address = 127.0.0.1
listen_port = ${overload_port}
tls_certificate_file = ${work_dir}/relay2-cert.pem
tls_private_key_file = ${work_dir}/relay2-key.pem
database_file = ${overload_db}
handshake_timeout_milliseconds = 6000
shutdown_timeout_milliseconds = 2000
max_connections = 3
endpoint_directory_capacity = 2
RELAY_EOF
"${relay_bin}" --config "${work_dir}/relay2.conf" >"${work_dir}/relay2.log" 2>&1 &
overload_relay_pid=$!
for _ in $(seq 1 50); do
  if (exec 3<>"/dev/tcp/127.0.0.1/${overload_port}") 2>/dev/null; then
    break
  fi
  sleep 0.1
done
kill -0 "${overload_relay_pid}" 2>/dev/null || fail "overload relay did not start"
sample_relay "phase-c-baseline" "${overload_relay_pid}" "${overload_url}" \
  "${work_dir}/ca.pem" "${work_dir}/relay2-baseline.txt"
overload_baseline_rss=$(proc_rss "${overload_relay_pid}")
overload_baseline_fds=$(proc_fds "${overload_relay_pid}")

mkdir -p "${work_dir}/phase-c"
chmod 700 "${work_dir}/phase-c"
for index in $(seq 1 "${overload_participants}"); do
  overload_db_profile="${work_dir}/phase-c/p-${index}.sqlite"
  SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" init-profile "${overload_db_profile}" matrix.overload \
    >"${work_dir}/phase-c/init-${index}.log" 2>&1 || fail "overload init-profile #${index} failed"
  SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" enroll "${overload_db_profile}" matrix.overload \
    "${overload_url}" "${work_dir}/ca.pem" "${tenant}" "${token}" \
    >"${work_dir}/phase-c/enroll-${index}.log" 2>&1 || fail "overload enroll #${index} failed"
done
for index in $(seq 1 "${overload_participants}"); do
  SSL_CERT_FILE="${work_dir}/ca.pem" "${matrix_bin}" run \
    "${work_dir}/phase-c/p-${index}.sqlite" matrix.overload \
    "${overload_url}" "${work_dir}/ca.pem" "${tenant}" 30000 \
    --role responder --hold-ms 4000 --authenticate-budget-ms 8000 \
    >"${work_dir}/phase-c/run-${index}.log" 2>&1 &
  participant_pids+=("$!")
done
for index in $(seq 1 "${overload_participants}"); do
  pid=${participant_pids[$((index - 1))]}
  wait_proc_exit "${pid}" 90 || fail "overload participant #${index} did not exit"
  wait "${pid}" 2>/dev/null || true
done
participant_pids=()

sample_relay "phase-c-final" "${overload_relay_pid}" "${overload_url}" \
  "${work_dir}/ca.pem" "${work_dir}/relay2-final.txt"
conn_rejected=$(metric_of "${work_dir}/relay2-final.txt" heyaki_relay_capacity_rejected_total)
endpoint_rejected=$(metric_of "${work_dir}/relay2-final.txt" heyaki_relay_endpoints_capacity_rejected_total)
table_rejected=$(metric_of "${work_dir}/relay2-final.txt" heyaki_relay_endpoint_table_capacity_rejected_total)
(( conn_rejected >= 1 )) ||
  fail "expected connection capacity rejections with max_connections=3, got ${conn_rejected}"
(( endpoint_rejected + table_rejected >= 1 )) ||
  fail "expected endpoint directory rejections with capacity=2, got endpoints=${endpoint_rejected} table=${table_rejected}"

# Graceful exits must leave the tight relay fully drained (session_cleanup
# removes the lease and the endpoint entry). active_sessions reads as 1 with
# everything gone because the metrics scrape itself holds the one live TLS
# connection — the baseline scrape shows the same value.
sleep 4
sample_relay "phase-c-drained" "${overload_relay_pid}" "${overload_url}" \
  "${work_dir}/ca.pem" "${work_dir}/relay2-drained.txt"
for family in heyaki_relay_endpoint_table_entries \
  heyaki_relay_lease_entries; do
  value=$(metric_of "${work_dir}/relay2-drained.txt" "$family")
  [[ "${value}" == "0" ]] ||
    fail "overload relay did not drain: ${family}=${value}"
done
value=$(metric_of "${work_dir}/relay2-drained.txt" heyaki_relay_active_sessions)
(( value <= 1 )) ||
  fail "overload relay active_sessions=${value} above scrape-only baseline after drain"
overload_final_rss=$(proc_rss "${overload_relay_pid}")
overload_final_fds=$(proc_fds "${overload_relay_pid}")
(( overload_final_rss <= overload_baseline_rss + 2 * rss_growth_kb )) ||
  fail "overload relay rss growth ${overload_baseline_rss}->${overload_final_rss} KB exceeds gate"
(( overload_final_fds <= overload_baseline_fds + 32 )) ||
  fail "overload relay fd growth ${overload_baseline_fds}->${overload_final_fds} exceeds gate"

ready_survivors=0
for index in $(seq 1 "${overload_participants}"); do
  if grep -q 'relay_state=ready' "${work_dir}/phase-c/run-${index}.log" 2>/dev/null; then
    ready_survivors=$((ready_survivors + 1))
  fi
done
(( ready_survivors >= 3 )) ||
  fail "only ${ready_survivors}/${overload_participants} overload participants stayed login-capable"

kill -TERM "${overload_relay_pid}" 2>/dev/null || true
wait_proc_exit "${overload_relay_pid}" 15 || kill -KILL "${overload_relay_pid}" 2>/dev/null || true
wait "${overload_relay_pid}" 2>/dev/null || true
overload_relay_pid=""
kill -TERM "${relay_pid}" 2>/dev/null || true
wait_proc_exit "${relay_pid}" 15 || kill -KILL "${relay_pid}" 2>/dev/null || true
wait "${relay_pid}" 2>/dev/null || true
relay_pid=""

log "OK session_cycles=${session_cycles} churn_participants=${churn_participants} overload_participants=${overload_participants}"
printf 'M9_SOAK_OK session_cycles=%s churn_participants=%s overload_participants=%s\n' \
  "${session_cycles}" "${churn_participants}" "${overload_participants}"
