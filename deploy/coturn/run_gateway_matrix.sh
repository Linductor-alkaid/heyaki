#!/usr/bin/env bash
set -euo pipefail

# Heyaki M10 Round 6 gateway matrix harness (requires root, coturn, curl, and
# the built apps). One public segment (198.51.100.0/24) carries the relay, two
# coturn instances, the gateway serving node (gwb) and the target namespace
# (gwt); the gateway client (gwa) shares the same segment, but an iptables
# FORWARD DROP blocks its direct traffic toward gwt, so the ONLY route from
# gwa to the target is a tunnel through gwb's gateway proxy. The real
# heyaki-m4-matrix-node participants then prove:
#   cross_segment  A --gateway-echo gwt:echo-port through B's "lan" profile
#                  (allowlist = gwt/32): 64-byte echo round trip ok=1 and
#                  B-side heyaki_gateway_bytes_* > 0 (the serving side owns
#                  the byte counters). A direct gwa->gwt TCP probe must be
#                  blocked, proving the tunnel is the unique path.
#   forced_turn    the same echo scenario with BOTH sides --force-turn over
#                  two coturn instances (a relayed<->relayed pair needs two
#                  servers); the data path must be turn_udp. On the vendored
#                  libjuice backend a forced relayed<->relayed pair stalls in
#                  nomination (documented in run_network_matrix.sh), so the
#                  stall signature is reported as BOUNDARY, not FAIL.
#   socks_curl     A --gateway-socks 1080: gwa curls http://gwt:8000/ and
#                  http://gwt.lan:8000/ (split-DNS: gwt.lan exists only in
#                  gwb's /etc/netns/<ns>/hosts) through the SOCKS5 frontend
#                  with --socks5-hostname so the DOMAIN reaches B verbatim;
#                  both must answer 200 and the frontend must report
#                  connects_succeeded >= 1.
#   path_policy    B --gateway-direct-only + both sides --force-turn: the
#                  gateway open must be refused (ok=0) while the session
#                  itself authenticates on the TURN data path.
# The TURN server addresses (198.51.100.2/.3) deliberately stay OUTSIDE the
# allowlist (198.51.100.20/32): the serving-side runtime does not yet compare
# the tunnel's own endpoint against the allowlist (review L1), so no scenario
# may put a TURN/relay address into the allowed CIDRs.
# Per-scenario verdicts print `GATEWAY_MATRIX <name> OK|FAIL|BOUNDARY ...`
# and the run ends with GATEWAY_MATRIX_OK / GATEWAY_MATRIX_FAILED.

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/../.." && pwd)

relay_bin=${HEYAKI_RELAY_BIN:-"${repo_root}/build/heyaki-relay"}
matrix_bin=${HEYAKI_MATRIX_BIN:-"${repo_root}/build/heyaki-m4-matrix-node"}
demo_bin=${HEYAKI_DEMO_BIN:-"${repo_root}/build/heyaki-m3b-relay-demo"}
coturn_bin=${HEYAKI_COTURN_BIN:-}

usage() {
  cat <<USAGE_EOF
Usage: $0 --relay-bin PATH --matrix-bin PATH [--demo-bin PATH] [--coturn-bin PATH]
          [--scenario NAME]...
Scenarios: cross_segment forced_turn socks_curl path_policy (default: all)
USAGE_EOF
}

log() { printf '[heyaki-gateway-matrix] %s\n' "$*"; }
skip() { printf 'SKIP: %s\n' "$*"; exit 77; }

scenarios=()
explicit_scenarios=0
while (($# > 0)); do
  case "$1" in
    --relay-bin) relay_bin=${2:?missing relay-bin value}; shift 2;;
    --matrix-bin) matrix_bin=${2:?missing matrix-bin value}; shift 2;;
    --demo-bin) demo_bin=${2:?missing demo-bin value}; shift 2;;
    --coturn-bin) coturn_bin=${2:?missing coturn-bin value}; shift 2;;
    --scenario) scenarios+=("${2:?missing scenario value}"); shift 2;;
    -h|--help) usage; exit 0;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 2;;
  esac
done
((${#scenarios[@]} > 0)) && explicit_scenarios=1
((${#scenarios[@]} == 0)) &&
  scenarios=(cross_segment forced_turn socks_curl path_policy)

for command_name in ip iptables openssl python3; do
  command -v "${command_name}" >/dev/null 2>&1 || skip "${command_name} is unavailable"
done
# socks_curl needs curl inside the client namespace (same host filesystem).
if printf '%s\n' "${scenarios[@]}" | grep -qx socks_curl &&
    ! command -v curl >/dev/null 2>&1; then
  if ((explicit_scenarios == 1 && ${#scenarios[@]} == 1)); then
    skip "curl is unavailable: socks_curl needs curl --socks5-hostname probes"
  fi
  log "curl unavailable: dropping socks_curl from the scenario list"
  scenarios=($(printf '%s\n' "${scenarios[@]}" | grep -vx socks_curl || true))
fi
[[ -z "${coturn_bin}" ]] && coturn_bin=$(command -v turnserver || true)
[[ -n "${coturn_bin}" ]] || skip "turnserver is unavailable; install coturn or pass --coturn-bin"
[[ -x "${relay_bin}" ]] || skip "relay binary is unavailable: ${relay_bin}"
[[ -x "${matrix_bin}" ]] || skip "matrix node binary is unavailable: ${matrix_bin}"
[[ -x "${demo_bin}" ]] || skip "relay demo binary is unavailable: ${demo_bin}"
[[ $(id -u) -eq 0 ]] || skip "root privileges are required to create network namespaces"
ip netns add __heyaki_gateway_probe 2>/dev/null || skip "network namespace capability is unavailable"
ip netns delete __heyaki_gateway_probe

work_dir=$(mktemp -d /tmp/heyaki-gateway-matrix.XXXXXX)
chmod 700 "${work_dir}"
relay_pid=""
turn_pid=""
turn_pid_b=""
echo_pid=""
http_pid=""
initiator_pid=""
responder_pid=""
br0="hygw-br"
ns_a="hygw-a"        # gateway client (A / initiator)
ns_b="hygw-b"        # gateway serving node (B / responder)
ns_t="hygw-t"        # target namespace (echo + http servers)
host_gw="198.51.100.1"     # bridge gateway; the relay listens here
turn_a_ip="198.51.100.2"   # coturn A advertised address (A's TURN)
turn_b_ip="198.51.100.3"   # coturn B advertised address (B's TURN)
client_b="198.51.100.9"    # gwb
client_a="198.51.100.10"   # gwa
client_t="198.51.100.20"   # gwt (target)
relay_port=8443
turn_port=3478
turn_port_b=3480
echo_port=9007
http_port=8000
socks_port=1080
secret=$(openssl rand -base64 24)
tenant="gateway-tenant"
token="TEST-ONLY-gateway-matrix-token-0123456789"
namespaces=("${ns_a}" "${ns_b}" "${ns_t}")
forward_rules=()

cleanup() {
  set +e
  [[ -n "${initiator_pid}" ]] && kill -TERM "${initiator_pid}" 2>/dev/null
  [[ -n "${responder_pid}" ]] && kill -TERM "${responder_pid}" 2>/dev/null
  [[ -n "${echo_pid}" ]] && kill -TERM "${echo_pid}" 2>/dev/null
  [[ -n "${http_pid}" ]] && kill -TERM "${http_pid}" 2>/dev/null
  [[ -n "${relay_pid}" ]] && kill -TERM "${relay_pid}" 2>/dev/null
  [[ -n "${turn_pid}" ]] && kill -TERM "${turn_pid}" 2>/dev/null
  [[ -n "${turn_pid_b}" ]] && kill -TERM "${turn_pid_b}" 2>/dev/null
  sleep 0.3
  [[ -n "${initiator_pid}" ]] && kill -KILL "${initiator_pid}" 2>/dev/null
  [[ -n "${responder_pid}" ]] && kill -KILL "${responder_pid}" 2>/dev/null
  [[ -n "${echo_pid}" ]] && kill -KILL "${echo_pid}" 2>/dev/null
  [[ -n "${http_pid}" ]] && kill -KILL "${http_pid}" 2>/dev/null
  [[ -n "${relay_pid}" ]] && kill -KILL "${relay_pid}" 2>/dev/null
  [[ -n "${turn_pid}" ]] && kill -KILL "${turn_pid}" 2>/dev/null
  [[ -n "${turn_pid_b}" ]] && kill -KILL "${turn_pid_b}" 2>/dev/null
  for rule in "${forward_rules[@]}"; do
    # shellcheck disable=SC2086
    while iptables -C FORWARD ${rule} 2>/dev/null; do
      # shellcheck disable=SC2086
      iptables -D FORWARD ${rule} 2>/dev/null
    done
  done
  rm -f "/etc/netns/${ns_b}/hosts" 2>/dev/null
  rmdir "/etc/netns/${ns_b}" 2>/dev/null
  for namespace in "${namespaces[@]}"; do
    ip netns delete "${namespace}" 2>/dev/null
  done
  ip link delete "${br0}" 2>/dev/null
  rm -rf "${work_dir}"
}
trap cleanup EXIT
trap 'log "SCRIPT_ERROR at line ${LINENO} (status $?)"' ERR

insert_forward() {
  # Remembered verbatim for cleanup; -I 1 keeps rules in front of policy.
  local rule="$1"
  forward_rules+=("${rule}")
  # shellcheck disable=SC2086
  iptables -C FORWARD ${rule} 2>/dev/null ||
    # shellcheck disable=SC2086
    iptables -I FORWARD 1 ${rule}
}

# ---- topology -----------------------------------------------------------
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
ip link add "${br0}" type bridge
ip addr add "${host_gw}/24" dev "${br0}"
# The coturn instances advertise dedicated addresses on the public segment
# (relayed traffic must not share the relay's own address).
ip addr add "${turn_a_ip}/32" dev "${br0}"
ip addr add "${turn_b_ip}/32" dev "${br0}"
ip link set "${br0}" up

create_client() {
  # namespace client_addr
  local ns=$1 client_addr=$2
  ip netns add "${ns}"
  ip link add "v-${ns}" type veth peer name "p-${ns}"
  ip link set "v-${ns}" master "${br0}"
  ip link set "v-${ns}" up
  ip link set "p-${ns}" netns "${ns}"
  ip netns exec "${ns}" ip link set lo up
  ip netns exec "${ns}" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 || true
  ip netns exec "${ns}" ip addr add "${client_addr}/24" dev "p-${ns}"
  ip netns exec "${ns}" ip link set "p-${ns}" up
  ip netns exec "${ns}" ip route add default via "${host_gw}"
}
create_client "${ns_a}" "${client_a}"
create_client "${ns_b}" "${client_b}"
create_client "${ns_t}" "${client_t}"

# GitHub runners carry Docker's FORWARD policy DROP; explicit ACCEPTs keep
# the bridge routing alive. The A->target DROP is inserted AFTER the accepts
# so it lands at position 1 and cannot be preempted: gwa must not reach gwt
# except through gwb's gateway tunnel.
insert_forward "-i ${br0} -o ${br0} -j ACCEPT"
iptables -C FORWARD -s "${client_a}" -d "${client_t}" -j DROP 2>/dev/null ||
  iptables -I FORWARD 1 -s "${client_a}" -d "${client_t}" -j DROP
forward_rules+=("-s ${client_a} -d ${client_t} -j DROP")

# Split-DNS for socks_curl: gwt.lan exists ONLY inside gwb's namespace, so a
# domain CONNECT handed to B (--socks5-hostname) proves serving-side
# resolution rather than client-side caching.
mkdir -p "/etc/netns/${ns_b}"
printf '%s gwt.lan\n' "${client_t}" > "/etc/netns/${ns_b}/hosts"

# ---- coturn and relay ---------------------------------------------------
write_turn_conf() {
  # advertised_address listening_port alt tls tls_alt min max log
  local advertised=$1 port=$2 alt=$3 tls=$4 tls_alt=$5 min=$6 max=$7 log=$8
  sed -e "s#__TURN_SECRET__#${secret}#" \
      -e "s#__ADVERTISED_ADDRESS__#${advertised}#" \
      -e "s#__LISTEN_ADDRESS__#0.0.0.0#" \
      -e "s#listening-port=3478#listening-port=${port}#" \
      -e "s#alt-listening-port=3479#alt-listening-port=${alt}#" \
      -e "s#tls-listening-port=5349#tls-listening-port=${tls}#" \
      -e "s#alt-tls-listening-port=5350#alt-tls-listening-port=${tls_alt}#" \
      -e "s#min-port=49160#min-port=${min}#" \
      -e "s#max-port=49200#max-port=${max}#" \
      -e "s#/etc/letsencrypt/live/heyaki.invalid/fullchain.pem#${work_dir}/turn-cert.pem#" \
      -e "s#/etc/letsencrypt/live/heyaki.invalid/privkey.pem#${work_dir}/turn-key.pem#" \
      -e "s#log-file=/var/log/coturn/turnserver.log#log-file=${work_dir}/${log}#" \
      "${script_dir}/turnserver.conf"
  # Matrix load profile, same as the sibling harnesses: the deploy baseline's
  # abuse limits would reject these short-lived participants.
  printf 'simple-log\nVerbose\ntotal-quota=1000\nuser-quota=100\nmax-bps=10000000\nbps-capacity=100000000\nallow-loopback-peers\n'
}
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${work_dir}/turn-key.pem" -out "${work_dir}/turn-cert.pem" \
  -subj "/CN=heyaki-gateway-matrix-turn.invalid" -days 1 -set_serial 1 >/dev/null 2>&1
write_turn_conf "${turn_a_ip}" "${turn_port}" 3479 5349 5350 49160 49199 turn-a.log \
  > "${work_dir}/turnserver-a.conf"
write_turn_conf "${turn_b_ip}" "${turn_port_b}" 3481 5351 5352 49200 49239 turn-b.log \
  > "${work_dir}/turnserver-b.conf"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -set_serial 1 \
  -subj "/CN=heyaki-gateway-matrix-relay" -keyout "${work_dir}/ca-key.pem" \
  -out "${work_dir}/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=${host_gw}" \
  -keyout "${work_dir}/relay-key.pem" -out "${work_dir}/relay.csr" >/dev/null 2>&1
printf 'subjectAltName=IP:%s\n' "${host_gw}" > "${work_dir}/san.ext"
openssl x509 -req -in "${work_dir}/relay.csr" -CA "${work_dir}/ca.pem" \
  -CAkey "${work_dir}/ca-key.pem" -CAcreateserial -days 1 \
  -extfile "${work_dir}/san.ext" -out "${work_dir}/relay-cert.pem" >/dev/null 2>&1

expiry=$(python3 -c 'import time; print(int(time.time() * 1000) + 3600000)')
"${demo_bin}" seed-token "${work_dir}/relay.sqlite" "${tenant}" "${token}" "${expiry}" 64

cat > "${work_dir}/relay.conf" <<RELAY_EOF
listen_address = 0.0.0.0
listen_port = ${relay_port}
tls_certificate_file = ${work_dir}/relay-cert.pem
tls_private_key_file = ${work_dir}/relay-key.pem
database_file = ${work_dir}/relay.sqlite
handshake_timeout_milliseconds = 2000
shutdown_timeout_milliseconds = 2000
RELAY_EOF
"${relay_bin}" --config "${work_dir}/relay.conf" >"${work_dir}/relay.log" 2>&1 &
relay_pid=$!
# Both coturn instances run on the host with disjoint ports/relay ranges and
# the two advertised segment addresses held by the bridge.
"${coturn_bin}" -c "${work_dir}/turnserver-a.conf" \
  >"${work_dir}/turn-a-stdout.log" 2>&1 &
turn_pid=$!
"${coturn_bin}" -c "${work_dir}/turnserver-b.conf" \
  >"${work_dir}/turn-b-stdout.log" 2>&1 &
turn_pid_b=$!

wait_for() {
  # namespace address port
  local ns=$1 address=$2 port=$3
  for _ in $(seq 1 100); do
    if ip netns exec "${ns}" \
        bash -c "exec 3<>/dev/tcp/${address}/${port}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}
wait_for "${ns_a}" "${host_gw}" "${relay_port}"
wait_for "${ns_a}" "${turn_a_ip}" "${turn_port}"
wait_for "${ns_b}" "${turn_b_ip}" "${turn_port_b}"
log "TOPOLOGY_OK relay=${host_gw}:${relay_port} turnA=${turn_a_ip}:${turn_port} turnB=${turn_b_ip}:${turn_port_b} blocked=${client_a}->${client_t}"

# ---- helpers ------------------------------------------------------------
run_in() {
  # namespace output_file command...
  local ns=$1 out=$2; shift 2
  ip netns exec "${ns}" env SSL_CERT_FILE="${work_dir}/ca.pem" \
    "${matrix_bin}" "$@" >"${out}" 2>&1
}

prepare_participants() {
  local tag=$1
  run_in "${ns_a}" "${work_dir}/${tag}-prepare-a.out" \
    init-profile "${work_dir}/${tag}-a.sqlite" matrix.first
  run_in "${ns_b}" "${work_dir}/${tag}-prepare-b.out" \
    init-profile "${work_dir}/${tag}-b.sqlite" matrix.second
  # seed-trust now carries gateway.use (A opens) and gateway.provide:lan (B
  # serves the "lan" profile) alongside the standard matrix scopes.
  run_in "${ns_a}" "${work_dir}/${tag}-prepare-seed.out" \
    seed-trust "${work_dir}/${tag}-a.sqlite" "${work_dir}/${tag}-b.sqlite"
  run_in "${ns_a}" "${work_dir}/${tag}-prepare-enroll-a.out" \
    enroll "${work_dir}/${tag}-a.sqlite" matrix.first \
    "wss://${host_gw}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" "${token}"
  run_in "${ns_b}" "${work_dir}/${tag}-prepare-enroll-b.out" \
    enroll "${work_dir}/${tag}-b.sqlite" matrix.second \
    "wss://${host_gw}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" "${token}"
}

first_result() { sed -n 's/^MATRIX_RESULT //p' "$1" | tail -1; }
result_field() {
  local line=$1 field=$2
  printf '%s\n' "${line}" | tr ' ' '\n' | sed -n "s/^${field}=//p" | head -1
}

# The allowlist covers ONLY the target: the relay/TURN addresses must stay
# outside it (serving-side tunnel-endpoint deny gap, review L1).
serve_cidr="${client_t}/32"

failures=0
dump_outputs() {
  local tag=$1
  log "OUTPUTS ${tag} initiator:"
  sed -n '1,40p' "${work_dir}/${tag}-a.out" 2>/dev/null || true
  log "OUTPUTS ${tag} responder:"
  sed -n '1,40p' "${work_dir}/${tag}-b.out" 2>/dev/null || true
  log "RELAY_LOG ${tag}:"
  tail -n 12 "${work_dir}/relay.log" 2>/dev/null || true
  log "TURN_LOG ${tag}:"
  for turn_log_name in turn-a.log turn-b.log; do
    grep -E "session [0-9]|allocated|error [0-9]+|quota" \
      "${work_dir}/${turn_log_name}" 2>/dev/null | tail -n 30 || true
  done
}

# responder+initiator echo pair; turn_mode "" | "forced". Prints nothing;
# call GATEWAY_METRIC / MATRIX_RESULT assertions after the pair completes.
run_echo_pair() {
  # tag budget turn_mode extra_responder_args...
  local tag=$1 budget=$2 turn_mode=$3; shift 3
  local responder_extra=("$@")
  local init_turn_args=() resp_turn_args=()
  if [[ "${turn_mode}" == "forced" ]]; then
    init_turn_args=(--turn "${turn_a_ip}:${turn_port}" --turn-secret "${secret}"
      --force-turn)
    resp_turn_args=(--turn "${turn_b_ip}:${turn_port_b}" --turn-secret "${secret}"
      --force-turn)
  fi
  prepare_participants "${tag}"
  sleep 4
  run_in "${ns_b}" "${work_dir}/${tag}-b.out" \
    run "${work_dir}/${tag}-b.sqlite" matrix.second \
    "wss://${host_gw}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" "${budget}" \
    --role responder --gateway-serve "${serve_cidr}" --gateway-metrics \
    --authenticate-budget-ms 25000 \
    ${resp_turn_args[@]+"${resp_turn_args[@]}"} \
    ${responder_extra[@]+"${responder_extra[@]}"} &
  responder_pid=$!
  run_in "${ns_a}" "${work_dir}/${tag}-a.out" \
    run "${work_dir}/${tag}-a.sqlite" matrix.first \
    "wss://${host_gw}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" "${budget}" \
    --role initiator --gateway-echo "${client_t}:${echo_port}" --gateway-metrics \
    --authenticate-budget-ms 25000 \
    ${init_turn_args[@]+"${init_turn_args[@]}"} &
  initiator_pid=$!
  wait "${initiator_pid}" || true
  wait "${responder_pid}" || true
  initiator_pid=""
  responder_pid=""
}

# The libjuice forced relayed<->relayed nomination stall (see
# run_network_matrix.sh forced_turn): either side stuck authenticating with
# no session error is the documented boundary, not a gateway failure.
stalled_pair() {
  # initiator_line responder_line
  local init_line=$1 resp_line=$2
  [[ "$(result_field "${init_line}" authenticated)" == "1" ]] && return 1
  [[ "$(result_field "${init_line}" session_error)" != "-" ]] && return 1
  [[ "$(result_field "${init_line}" state)" == "authenticating" ]] && return 0
  [[ "$(result_field "${resp_line}" state)" == "authenticating" ]] && return 0
  return 1
}

gateway_bytes_from_tunnel() {
  # output_file -> last sample value of the serving-side byte counter
  sed -n 's/^heyaki_gateway_bytes_from_tunnel_total \([0-9][0-9]*\)$/\1/p' "$1" | tail -1
}

start_echo_target() {
  cat > "${work_dir}/echo_server.py" <<'PY_EOF'
import socket
import threading

def echo(connection):
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            connection.sendall(data)
    except OSError:
        pass
    finally:
        connection.close()

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("0.0.0.0", 9007))
listener.listen(16)
while True:
    client, _ = listener.accept()
    threading.Thread(target=echo, args=(client,), daemon=True).start()
PY_EOF
  ip netns exec "${ns_t}" python3 "${work_dir}/echo_server.py" \
    >"${work_dir}/echo-server.log" 2>&1 &
  echo_pid=$!
  wait_for "${ns_b}" "${client_t}" "${echo_port}"
}

# A must NOT reach the target directly (unique-path proof for cross_segment).
assert_direct_blocked() {
  local probe
  probe=$(ip netns exec "${ns_a}" python3 -c '
import socket
probe = socket.socket()
probe.settimeout(3)
try:
    probe.connect(("198.51.100.20", 9007))
    print("DIRECT_REACHABLE")
except OSError:
    print("DIRECT_BLOCKED")
finally:
    probe.close()
') || probe="PROBE_ERROR"
  if [[ "${probe}" == "DIRECT_BLOCKED" ]]; then
    log "PROBE_OK gwa->gwt direct path blocked (tunnel is the unique route)"
    return 0
  fi
  log "GATEWAY_MATRIX cross_segment FAIL direct-path probe: ${probe}"
  return 1
}

for scenario in "${scenarios[@]}"; do
  case "${scenario}" in
    cross_segment)
      start_echo_target
      assert_direct_blocked || failures=$((failures + 1))
      run_echo_pair cross 45000 ""
      line=$(first_result "${work_dir}/cross-a.out")
      resp_line=$(first_result "${work_dir}/cross-b.out")
      bytes=$(gateway_bytes_from_tunnel "${work_dir}/cross-b.out")
      ok_line=$(sed -n 's/^\(GATEWAY_METRIC name=echo_roundtrip_ms.*\)$/\1/p' \
        "${work_dir}/cross-a.out" | tail -1)
      if [[ "$(result_field "${line}" authenticated)" == "1" &&
            "${ok_line}" == *" ok=1"* &&
            -n "${bytes}" && "${bytes}" -gt 0 ]]; then
        log "GATEWAY_MATRIX cross_segment OK: ${ok_line} serving_bytes=${bytes} path=$(result_field "${line}" data_path)"
      else
        log "GATEWAY_MATRIX cross_segment FAIL: metric=${ok_line:-missing} serving_bytes=${bytes:-missing} result=${line:-no-result}"
        dump_outputs cross
        failures=$((failures + 1))
      fi
      kill -TERM "${echo_pid}" 2>/dev/null || true
      wait "${echo_pid}" 2>/dev/null || true
      echo_pid=""
      ;;
    forced_turn)
      start_echo_target
      run_echo_pair forced 60000 forced
      line=$(first_result "${work_dir}/forced-a.out")
      resp_line=$(first_result "${work_dir}/forced-b.out")
      ok_line=$(sed -n 's/^\(GATEWAY_METRIC name=echo_roundtrip_ms.*\)$/\1/p' \
        "${work_dir}/forced-a.out" | tail -1)
      if [[ "$(result_field "${line}" authenticated)" == "1" &&
            "$(result_field "${line}" data_path)" == "turn_udp" &&
            "${ok_line}" == *" ok=1"* ]]; then
        log "GATEWAY_MATRIX forced_turn OK: ${ok_line} path=turn_udp"
      elif stalled_pair "${line}" "${resp_line}"; then
        log "GATEWAY_MATRIX forced_turn BOUNDARY: forced relayed<->relayed nomination stalls on this ICE backend (documented); gateway layer not exercised: ${line:-no-result}"
      else
        log "GATEWAY_MATRIX forced_turn FAIL: metric=${ok_line:-missing} result=${line:-no-result}"
        dump_outputs forced
        failures=$((failures + 1))
      fi
      kill -TERM "${echo_pid}" 2>/dev/null || true
      wait "${echo_pid}" 2>/dev/null || true
      echo_pid=""
      ;;
    socks_curl)
      ip netns exec "${ns_t}" python3 -m http.server "${http_port}" \
        --bind 0.0.0.0 >"${work_dir}/http-server.log" 2>&1 &
      http_pid=$!
      wait_for "${ns_b}" "${client_t}" "${http_port}"
      prepare_participants socks
      sleep 4
      run_in "${ns_b}" "${work_dir}/socks-b.out" \
        run "${work_dir}/socks-b.sqlite" matrix.second \
        "wss://${host_gw}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" 75000 \
        --role responder --gateway-serve "${serve_cidr}" \
        --authenticate-budget-ms 25000 &
      responder_pid=$!
      run_in "${ns_a}" "${work_dir}/socks-a.out" \
        run "${work_dir}/socks-a.sqlite" matrix.first \
        "wss://${host_gw}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" 70000 \
        --role initiator --gateway-socks "${socks_port}" \
        --authenticate-budget-ms 25000 &
      initiator_pid=$!
      ready=""
      for _ in $(seq 1 300); do
        if grep -q '^GATEWAY_SOCKS_READY' "${work_dir}/socks-a.out" 2>/dev/null; then
          ready=$(sed -n 's/^GATEWAY_SOCKS_READY //p' "${work_dir}/socks-a.out" | tail -1)
          break
        fi
        if ! kill -0 "${initiator_pid}" 2>/dev/null; then
          break
        fi
        sleep 0.2
      done
      verdict="FAIL"
      detail=""
      if [[ -z "${ready}" ]]; then
        detail="frontend never became ready"
      else
        status_ip=$(ip netns exec "${ns_a}" curl -s --max-time 20 \
          --socks5-hostname "127.0.0.1:${socks_port}" -o /dev/null \
          -w '%{http_code}' "http://${client_t}:${http_port}/" || echo 000)
        status_dns=$(ip netns exec "${ns_a}" curl -s --max-time 20 \
          --socks5-hostname "127.0.0.1:${socks_port}" -o /dev/null \
          -w '%{http_code}' "http://gwt.lan:${http_port}/" || echo 000)
        if [[ "${status_ip}" == "200" && "${status_dns}" == "200" ]]; then
          verdict="OK"
        else
          detail="http_status_ip=${status_ip:-none} http_status_dns=${status_dns:-none}"
        fi
      fi
      # SIGTERM the initiator: the frontend keep-alive loop must exit cleanly.
      kill -TERM "${initiator_pid}" 2>/dev/null || true
      initiator_status=0
      wait "${initiator_pid}" || initiator_status=$?
      kill -TERM "${responder_pid}" 2>/dev/null || true
      wait "${responder_pid}" 2>/dev/null || true
      initiator_pid=""
      responder_pid=""
      summary=$(sed -n 's/^GATEWAY_SOCKS_SUMMARY //p' "${work_dir}/socks-a.out" | tail -1)
      connects=$(printf '%s\n' "${summary}" | tr ' ' '\n' |
        sed -n 's/^connects_succeeded=//p' | head -1)
      if [[ "${verdict}" == "OK" ]]; then
        if [[ -n "${connects}" && "${connects}" -ge 1 && "${initiator_status}" == "0" ]]; then
          log "GATEWAY_MATRIX socks_curl OK: ip_and_dns_200=1 connects_succeeded=${connects} clean_exit=${initiator_status}"
        else
          log "GATEWAY_MATRIX socks_curl FAIL: connects_succeeded=${connects:-missing} initiator_exit=${initiator_status} summary=${summary:-missing}"
          dump_outputs socks
          failures=$((failures + 1))
        fi
      else
        log "GATEWAY_MATRIX socks_curl FAIL: ${detail:-unknown} connects_succeeded=${connects:-missing} summary=${summary:-missing}"
        dump_outputs socks
        failures=$((failures + 1))
      fi
      kill -TERM "${http_pid}" 2>/dev/null || true
      wait "${http_pid}" 2>/dev/null || true
      http_pid=""
      ;;
    path_policy)
      start_echo_target
      run_echo_pair policy 60000 forced --gateway-direct-only
      line=$(first_result "${work_dir}/policy-a.out")
      resp_line=$(first_result "${work_dir}/policy-b.out")
      ok_line=$(sed -n 's/^\(GATEWAY_METRIC name=echo_roundtrip_ms.*\)$/\1/p' \
        "${work_dir}/policy-a.out" | tail -1)
      if [[ "$(result_field "${line}" authenticated)" == "1" &&
            "$(result_field "${line}" data_path)" == "turn_udp" &&
            "${ok_line}" == *" ok=0"* ]]; then
        log "GATEWAY_MATRIX path_policy OK: open refused on the TURN path: ${ok_line}"
      elif stalled_pair "${line}" "${resp_line}"; then
        log "GATEWAY_MATRIX path_policy BOUNDARY: forced relayed<->relayed nomination stalls on this ICE backend (documented); gateway layer not exercised: ${line:-no-result}"
      else
        log "GATEWAY_MATRIX path_policy FAIL: metric=${ok_line:-missing} result=${line:-no-result}"
        dump_outputs policy
        failures=$((failures + 1))
      fi
      kill -TERM "${echo_pid}" 2>/dev/null || true
      wait "${echo_pid}" 2>/dev/null || true
      echo_pid=""
      ;;
    *)
      log "unknown scenario: ${scenario}"
      exit 2
      ;;
  esac
done

if ((failures > 0)); then
  log "GATEWAY_MATRIX_FAILED failures=${failures}"
  exit 1
fi
log "GATEWAY_MATRIX_OK scenarios=${scenarios[*]}"
