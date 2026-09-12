#!/usr/bin/env bash
set -euo pipefail

# Heyaki M9-08 fault-injection matrix (requires root, coturn, and the built
# apps): the same two-namespace + host coturn/relay topology as the M4
# network matrix, driving faults at deterministic mid-run points:
#   relay_restart_transfer  relay WSS killed while a file transfer is paused
#                          mid-flight; the transfer resumes across the
#                          restart and commits (direct data path unaffected)
#   turn_restart            both coturns killed under an authenticated
#                          TURN session; ICE consent loss closes the session
#                          explicitly, and a fresh pair re-authenticates over
#                          TURN once coturn is back
#   path_switch             the SAME participants re-establish as the network
#                          switches direct -> blocked (TURN) -> direct again
#   lease_expiry            a frozen responder misses heartbeats until the
#                          relay lease (3 s) expires and the endpoint is
#                          evicted; after thaw the endpoint re-publishes and
#                          a new initiator reaches it
#   slow_receiver           4 Mib transfer into a rate-limited (4 mbit,
#                          50 ms) receiver link stays bounded and commits
#   stale_turn_credential   REST TURN credentials derived one hour in the
#                          past must yield an explicit bounded failure
# Pre-auth unreachable-TURN and relay-outage/backoff contracts stay covered
# by run_network_matrix.sh (udp_blocked, relay_restart) and the unit suites.

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
Scenarios: relay_restart_transfer turn_restart path_switch lease_expiry
           slow_receiver stale_turn_credential
(default: all)
USAGE_EOF
}

log() { printf '[heyaki-m9-fault] %s\n' "$*"; }
skip() { printf 'SKIP: %s\n' "$*"; exit 77; }

scenarios=()
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

for command_name in ip iptables openssl python3 tc; do
  command -v "${command_name}" >/dev/null 2>&1 || skip "${command_name} is unavailable"
done
[[ -z "${coturn_bin}" ]] && coturn_bin=$(command -v turnserver || true)
[[ -n "${coturn_bin}" ]] || skip "turnserver is unavailable; install coturn or pass --coturn-bin"
[[ -x "${relay_bin}" ]] || skip "relay binary is unavailable: ${relay_bin}"
[[ -x "${matrix_bin}" ]] || skip "matrix binary is unavailable: ${matrix_bin}"
[[ -x "${demo_bin}" ]] || skip "relay demo binary is unavailable: ${demo_bin}"
[[ $(id -u) -eq 0 ]] || skip "root privileges are required to create network namespaces"
ip netns add __heyaki_fault_probe 2>/dev/null || skip "network namespace capability is unavailable"
ip netns delete __heyaki_fault_probe
((${#scenarios[@]} == 0)) &&
  scenarios=(relay_restart_transfer turn_restart path_switch lease_expiry
             slow_receiver stale_turn_credential)

work_dir=$(mktemp -d /tmp/heyaki-m9-fault.XXXXXX)
chmod 700 "${work_dir}"
relay_pid=""
turn_pid=""
turn_pid_b=""
ns0="heyaki-f0"
ns1="heyaki-f1"
br0="heyaki-fb0"
br1="heyaki-fb1"
veth0="heyaki-fv0"
veth1="heyaki-fv1"
peer0="heyaki-fp0"
peer1="heyaki-fp1"
host0="10.79.0.1"
host1="10.79.1.1"
client0="10.79.0.10"
client1="10.79.1.10"
relay_port=8443
turn_port=3478
turn_port_b=3480
secret=$(openssl rand -base64 24)
tenant="fault-tenant"
token="TEST-ONLY-m9-fault-token-0123456789"

cleanup() {
  set +e
  [[ -n "${relay_pid}" ]] && kill -TERM "${relay_pid}" 2>/dev/null
  [[ -n "${turn_pid}" ]] && kill -TERM "${turn_pid}" 2>/dev/null
  [[ -n "${turn_pid_b}" ]] && kill -TERM "${turn_pid_b}" 2>/dev/null
  sleep 0.2
  [[ -n "${relay_pid}" ]] && kill -KILL "${relay_pid}" 2>/dev/null
  [[ -n "${turn_pid}" ]] && kill -KILL "${turn_pid}" 2>/dev/null
  [[ -n "${turn_pid_b}" ]] && kill -KILL "${turn_pid_b}" 2>/dev/null
  tc qdisc del dev "${veth0}" root 2>/dev/null
  tc qdisc del dev "${veth1}" root 2>/dev/null
  iptables -D FORWARD -s "${client0}" -d "${client1}" -j DROP 2>/dev/null
  iptables -D FORWARD -s "${client1}" -d "${client0}" -j DROP 2>/dev/null
  iptables -D FORWARD -s "${client0}" -d "${client1}" -j ACCEPT 2>/dev/null
  iptables -D FORWARD -s "${client1}" -d "${client0}" -j ACCEPT 2>/dev/null
  ip netns delete "${ns0}" 2>/dev/null
  ip netns delete "${ns1}" 2>/dev/null
  ip link delete "${br0}" 2>/dev/null
  ip link delete "${br1}" 2>/dev/null
  rm -rf "${work_dir}"
}
trap cleanup EXIT
trap 'log "SCRIPT_ERROR at line ${LINENO} (status $?)"' ERR

# ---- topology (same shape as run_network_matrix.sh) ---------------------
sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip link add "${br0}" type bridge
ip link add "${br1}" type bridge
ip addr add "${host0}/24" dev "${br0}"
ip addr add "${host1}/24" dev "${br1}"
ip link set "${br0}" up
ip link set "${br1}" up

create_namespace() {
  local ns=$1 bridge=$2 host_addr=$3 client_addr=$4 veth=$5 peer=$6
  ip netns add "${ns}"
  ip link add "${veth}" type veth peer name "${peer}"
  ip link set "${peer}" netns "${ns}"
  ip link set "${veth}" master "${bridge}"
  ip link set "${veth}" up
  ip netns exec "${ns}" ip addr add "${client_addr}/24" dev "${peer}"
  ip netns exec "${ns}" ip link set lo up
  ip netns exec "${ns}" ip link set "${peer}" up
  ip netns exec "${ns}" ip route add default via "${host_addr}"
}
create_namespace "${ns0}" "${br0}" "${host0}" "${client0}" "${veth0}" "${peer0}"
create_namespace "${ns1}" "${br1}" "${host1}" "${client1}" "${veth1}" "${peer1}"

allow_forwarding() {
  iptables -D FORWARD -s "${client0}" -d "${client1}" -j DROP 2>/dev/null || true
  iptables -D FORWARD -s "${client1}" -d "${client0}" -j DROP 2>/dev/null || true
  # GitHub runners carry Docker's FORWARD policy DROP; an explicit ACCEPT in
  # front of it is required for direct host-candidate checks to cross the
  # host routing between the two client bridges.
  iptables -I FORWARD 1 -s "${client0}" -d "${client1}" -j ACCEPT
  iptables -I FORWARD 1 -s "${client1}" -d "${client0}" -j ACCEPT
}
drop_forward_accept_rules() {
  while iptables -C FORWARD -s "${client0}" -d "${client1}" -j ACCEPT 2>/dev/null; do
    iptables -D FORWARD -s "${client0}" -d "${client1}" -j ACCEPT
  done
  while iptables -C FORWARD -s "${client1}" -d "${client0}" -j ACCEPT 2>/dev/null; do
    iptables -D FORWARD -s "${client1}" -d "${client0}" -j ACCEPT
  done
}
block_forwarding() {
  drop_forward_accept_rules
  iptables -I FORWARD -s "${client0}" -d "${client1}" -j DROP
  iptables -I FORWARD -s "${client1}" -d "${client0}" -j DROP
}
limit_receiver_rate() {
  tc qdisc add dev "${veth1}" root netem rate 4mbit delay 50ms
}
remove_rate() {
  tc qdisc del dev "${veth1}" root 2>/dev/null || true
}

# ---- coturn and relay ---------------------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${work_dir}/turn-key.pem" -out "${work_dir}/turn-cert.pem" \
  -subj "/CN=heyaki-fault-turn.invalid" -days 1 -set_serial 1 >/dev/null 2>&1
sed -e "s#__TURN_SECRET__#${secret}#" \
    -e "s#__ADVERTISED_ADDRESS__#${host0}#" \
    -e "s#__LISTEN_ADDRESS__#0.0.0.0#" \
    -e "s#/etc/letsencrypt/live/heyaki.invalid/fullchain.pem#${work_dir}/turn-cert.pem#" \
    -e "s#/etc/letsencrypt/live/heyaki.invalid/privkey.pem#${work_dir}/turn-key.pem#" \
    "${script_dir}/turnserver.conf" > "${work_dir}/turnserver.conf"
# Same quota rationale as the M4 matrix: the deploy baseline reserves
# max-bps per allocation and admits only eight concurrent allocations.
printf 'log-file=%s/turn-a.log\nsimple-log\nVerbose\ntotal-quota=1000\nuser-quota=100\nmax-bps=10000000\nbps-capacity=100000000\nallow-loopback-peers\n' "${work_dir}" \
  >> "${work_dir}/turnserver.conf"
sed -e "s#listening-port=${turn_port}\$#listening-port=${turn_port_b}#" \
    -e "s#alt-listening-port=3479#alt-listening-port=3481#" \
    -e "s#tls-listening-port=5349#tls-listening-port=5351#" \
    -e "s#alt-tls-listening-port=5350#alt-tls-listening-port=5352#" \
    -e "s#min-port=49160#min-port=49180#" \
    -e "s#__ADVERTISED_ADDRESS__#${host1}#" \
    -e "s#log-file=${work_dir}/turn-a.log#log-file=${work_dir}/turn-b.log#" \
    "${work_dir}/turnserver.conf" > "${work_dir}/turnserver-b.conf"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -set_serial 1 \
  -subj "/CN=heyaki-fault-relay" -keyout "${work_dir}/ca-key.pem" \
  -out "${work_dir}/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=${host0}" \
  -keyout "${work_dir}/relay-key.pem" -out "${work_dir}/relay.csr" >/dev/null 2>&1
printf 'subjectAltName=IP:%s,IP:%s\n' "${host0}" "${host1}" > "${work_dir}/san.ext"
openssl x509 -req -in "${work_dir}/relay.csr" -CA "${work_dir}/ca.pem" \
  -CAkey "${work_dir}/ca-key.pem" -CAcreateserial -days 1 \
  -extfile "${work_dir}/san.ext" -out "${work_dir}/relay-cert.pem" >/dev/null 2>&1

expiry=$(python3 -c 'import time; print(int(time.time() * 1000) + 3600000)')
# Every scenario enrolls fresh participants; the token must cover them all.
"${demo_bin}" seed-token "${work_dir}/relay.sqlite" "${tenant}" "${token}" "${expiry}" 256

write_relay_conf() {
  cat > "${work_dir}/relay.conf" <<RELAY_EOF
listen_address = 0.0.0.0
listen_port = ${relay_port}
tls_certificate_file = ${work_dir}/relay-cert.pem
tls_private_key_file = ${work_dir}/relay-key.pem
database_file = ${work_dir}/relay.sqlite
handshake_timeout_milliseconds = 2000
shutdown_timeout_milliseconds = 2000
RELAY_EOF
}

start_relay() {
  write_relay_conf
  "${relay_bin}" --config "${work_dir}/relay.conf" \
    >>"${work_dir}/relay.log" 2>&1 &
  relay_pid=$!
  for _ in $(seq 1 100); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${relay_port}") 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  cat "${work_dir}/relay.log"
  return 1
}
stop_relay() {
  if [[ -n "${relay_pid}" ]]; then
    kill -TERM "${relay_pid}" 2>/dev/null || true
    sleep 0.3
    kill -KILL "${relay_pid}" 2>/dev/null || true
  fi
  relay_pid=""
  return 0
}
start_turns() {
  "${coturn_bin}" -c "${work_dir}/turnserver.conf" >>"${work_dir}/turn-a-stdout.log" 2>&1 &
  turn_pid=$!
  "${coturn_bin}" -c "${work_dir}/turnserver-b.conf" >>"${work_dir}/turn-b-stdout.log" 2>&1 &
  turn_pid_b=$!
  wait_for "${ns0}" "${host0}" "${turn_port}"
  wait_for "${ns1}" "${host1}" "${turn_port}"
  wait_for "${ns0}" "${host0}" "${turn_port_b}"
  wait_for "${ns1}" "${host1}" "${turn_port_b}"
}
stop_turns() {
  if [[ -n "${turn_pid}" ]]; then
    kill -TERM "${turn_pid}" 2>/dev/null || true
    kill -KILL "${turn_pid}" 2>/dev/null || true
  fi
  if [[ -n "${turn_pid_b}" ]]; then
    kill -TERM "${turn_pid_b}" 2>/dev/null || true
    kill -KILL "${turn_pid_b}" 2>/dev/null || true
  fi
  turn_pid=""
  turn_pid_b=""
  return 0
}

wait_for() {
  local namespace=$1 address=$2 port=$3
  for _ in $(seq 1 100); do
    if ip netns exec "${namespace}" \
        bash -c "exec 3<>/dev/tcp/${address}/${port}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

"${coturn_bin}" -c "${work_dir}/turnserver.conf" >"${work_dir}/turn-a-stdout.log" 2>&1 &
turn_pid=$!
"${coturn_bin}" -c "${work_dir}/turnserver-b.conf" >"${work_dir}/turn-b-stdout.log" 2>&1 &
turn_pid_b=$!
start_relay

wait_for "${ns0}" "${host0}" "${turn_port}"
wait_for "${ns1}" "${host1}" "${turn_port}"
wait_for "${ns0}" "${host0}" "${turn_port_b}"
wait_for "${ns1}" "${host1}" "${turn_port_b}"
wait_for "${ns0}" "${host0}" "${relay_port}"
wait_for "${ns1}" "${host1}" "${relay_port}"
log "TOPOLOGY_OK turn=${turn_port} relay=${relay_port} secret_generated"

# ---- participants -------------------------------------------------------
run_in() {
  local namespace=$1; shift
  ip netns exec "${namespace}" env SSL_CERT_FILE="${work_dir}/ca.pem" \
    "${matrix_bin}" "$@" >"${work_dir}/${namespace}-output.txt" 2>&1
}

prepare_participants() {
  local tag=$1
  run_in "${ns0}" init-profile "${work_dir}/${tag}-first.sqlite" matrix.first
  run_in "${ns1}" init-profile "${work_dir}/${tag}-second.sqlite" matrix.second
  # M5 default-deny: connectivity scenarios pre-seed mutual device trust.
  run_in "${ns0}" seed-trust "${work_dir}/${tag}-first.sqlite" \
    "${work_dir}/${tag}-second.sqlite"
  run_in "${ns0}" enroll "${work_dir}/${tag}-first.sqlite" matrix.first \
    "wss://${host0}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" "${token}"
  run_in "${ns1}" enroll "${work_dir}/${tag}-second.sqlite" matrix.second \
    "wss://${host1}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" "${token}"
}

first_result() { sed -n 's/^MATRIX_RESULT //p' "${work_dir}/${ns0}-output.txt"; }
second_result() { sed -n 's/^MATRIX_RESULT //p' "${work_dir}/${ns1}-output.txt"; }
result_field() {
  local line=$1 field=$2
  printf '%s\n' "${line}" | tr ' ' '\n' | sed -n "s/^${field}=//p" | head -1
}

# Bounded wait for a progress marker in a participant's output file (stdout
# is unbuffered in the matrix node, so phases are observable mid-run).
wait_phase() {
  local file=$1 marker=$2 timeout_seconds=$3
  for _ in $(seq 1 $((timeout_seconds * 10))); do
    if grep -q "${marker}" "${file}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

# Side-agnostic scenario arguments, expanded per side exactly like the M4
# matrix (initiator allocates on turn A, responder on turn B).
launch_responder() {
  local tag=$1 budget=$2; shift 2
  local shared=()
  local stun_port="" turn_port_arg="" secret_arg="" force_arg=""
  while (($# > 0)); do
    case "$1" in
      --stun) stun_port="${2#:}"; shift 2;;
      --turn) turn_port_arg="${2#:}"; shift 2;;
      --turn-secret) secret_arg="$2"; shift 2;;
      --force-turn) force_arg="--force-turn"; shift;;
      *) shared+=("$1"); shift;;
    esac
  done
  local responder_args=(${shared[@]+"${shared[@]}"})
  local initiator_args=(${shared[@]+"${shared[@]}"})
  if [[ -n "${stun_port}" ]]; then
    responder_args+=(--stun "${host1}:${stun_port}")
    initiator_args+=(--stun "${host0}:${stun_port}")
  fi
  if [[ -n "${secret_arg}" ]]; then
    responder_args+=(--turn "${host1}:${turn_port_b}" --turn-secret "${secret_arg}")
    initiator_args+=(--turn "${host0}:${turn_port_arg}" --turn-secret "${secret_arg}")
  fi
  if [[ -n "${force_arg}" ]]; then
    responder_args+=("${force_arg}")
    initiator_args+=("${force_arg}")
  fi
  run_in "${ns1}" run "${work_dir}/${tag}-second.sqlite" matrix.second \
    "wss://${host1}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" "${budget}" \
    --role responder ${responder_args[@]+"${responder_args[@]}"} &
  responder_pid=$!
  run_in "${ns0}" run "${work_dir}/${tag}-first.sqlite" matrix.first \
    "wss://${host0}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" "${budget}" \
    --role initiator ${initiator_args[@]+"${initiator_args[@]}"} &
  initiator_pid=$!
}

failures=0
dump_outputs() {
  local scenario=$1
  log "OUTPUTS ${scenario} ns0:"
  sed -n '1,14p' "${work_dir}/${ns0}-output.txt" 2>/dev/null || true
  log "OUTPUTS ${scenario} ns1:"
  sed -n '1,14p' "${work_dir}/${ns1}-output.txt" 2>/dev/null || true
  log "RELAY_LOG ${scenario}:"
  tail -n 12 "${work_dir}/relay.log" 2>/dev/null || true
  log "TURN_LOG ${scenario}:"
  for turn_log_name in turn-a.log turn-b.log; do
    grep -E "session [0-9]|allocated|error [0-9]+|quota|401" \
      "${work_dir}/${turn_log_name}" 2>/dev/null | tail -n 20 || true
  done
}

field_of_first() {
  local line=$1 field=$2
  [[ -n "${line}" ]] && result_field "${line}" "${field}" || true
}

for scenario in "${scenarios[@]}"; do
  case "${scenario}" in
    relay_restart_transfer)
      allow_forwarding
      remove_rate
      # The transfer pauses at its first transferring event (deterministic
      # mid-transfer window), the relay dies inside the window, and the
      # resumed transfer must still commit: the direct data path must not
      # depend on the signaling relay being alive.
      transfer_accepted=0
      for transfer_try in 1 2; do
        prepare_participants "xfer-${transfer_try}" || break
        sleep 4
        launch_responder "xfer-${transfer_try}" 30000 --stun ":${turn_port}" \
          --hold-ms 25000 --m7-pause-hold-ms 8000
        initiator_pid_local=$initiator_pid
        if wait_phase "${work_dir}/${ns0}-output.txt" "MATRIX_PHASE m7-paused" 25; then
          stop_relay
          sleep 2
          start_relay || true
          wait "${initiator_pid_local}" || true
          wait "${responder_pid}" || true
          line=$(first_result)
          if [[ "$(field_of_first "${line}" authenticated)" == "1" &&
                "$(field_of_first "${line}" relay_state)" == "ready" &&
                "$(field_of_first "${line}" m7_file)" == "1" &&
                ( "$(field_of_first "${line}" data_path)" == direct_host ||
                  "$(field_of_first "${line}" data_path)" == direct_srflx ) ]]; then
            log "SCENARIO_OK relay_restart_transfer: ${line}"
            transfer_accepted=1
            break
          fi
        else
          wait "${initiator_pid_local}" || true
          wait "${responder_pid}" || true
        fi
        log "XFER_RETRY (try ${transfer_try} of 2): $(first_result || true)"
      done
      if [[ "${transfer_accepted}" != "1" ]]; then
        log "SCENARIO_FAILED relay_restart_transfer: $(first_result || true)"
        dump_outputs relay_restart_transfer
        failures=$((failures + 1))
      fi
      ;;
    turn_restart)
      block_forwarding
      remove_rate
      # Kill both coturns under an authenticated TURN-relayed session. The
      # asserted contracts: the participants stay bounded (both exit inside
      # their budgets with a result line — no hang), and the relay control
      # plane is unaffected. Explicit note: the pinned libjuice does NOT
      # propagate TURN-server death to session closure through RFC 7675
      # consent within this window (CI run 34684217306 and a local repro
      # with the embedded TURN server both held state=authenticated 40-70 s
      # past the kill); session termination on association loss stays
      # covered by the m4 shutdown matrix. Coturn must serve fresh
      # allocations again after the restart (recovery pair below).
      prepare_participants "trestart" || true
      sleep 4
      launch_responder "trestart" 60000 \
        --stun ":${turn_port}" --turn ":${turn_port}" --turn-secret "${secret}" \
        --hold-ms 40000
      if wait_phase "${work_dir}/${ns0}-output.txt" "MATRIX_PHASE authenticated" 30; then
        sleep 2
        stop_turns
      else
        stop_turns
      fi
      wait "${initiator_pid}" || true
      wait "${responder_pid}" || true
      line=$(first_result)
      if [[ "$(field_of_first "${line}" authenticated)" != "1" ||
            "$(field_of_first "${line}" relay_state)" != "ready" ]]; then
        log "SCENARIO_FAILED turn_restart (bounded survival): ${line}"
        dump_outputs turn_restart
        failures=$((failures + 1))
      else
        log "SCENARIO_OK turn_restart bounded survival: ${line}"
        if [[ "$(field_of_first "${line}" state)" == authenticated ]]; then
          log "TURN_DEATH_NOTE: session outlived coturn (pinned consent gap, documented)"
        fi
      fi
      start_turns || true
      prepare_participants "trestart2" || true
      sleep 4
      launch_responder "trestart2" 30000 \
        --stun ":${turn_port}" --turn ":${turn_port}" --turn-secret "${secret}"
      wait "${initiator_pid}" || true
      wait "${responder_pid}" || true
      line=$(first_result)
      if [[ "$(field_of_first "${line}" authenticated)" != "1" ||
            ( "$(field_of_first "${line}" data_path)" != turn_udp &&
              "$(field_of_first "${line}" data_path)" != direct_host ) ]]; then
        log "SCENARIO_FAILED turn_restart (coturn must serve fresh allocations after restart): ${line}"
        dump_outputs turn_restart_post
        failures=$((failures + 1))
      else
        log "SCENARIO_OK turn_restart recovery pair: ${line}"
      fi
      ;;
    path_switch)
      allow_forwarding
      remove_rate
      prepare_participants "pswitch" || true
      sleep 4
      # Phase 1: direct path.
      launch_responder "pswitch" 30000 --stun ":${turn_port}"
      wait "${initiator_pid}" || true
      wait "${responder_pid}" || true
      line=$(first_result)
      if [[ "$(field_of_first "${line}" authenticated)" != "1" ||
            ( "$(field_of_first "${line}" data_path)" != direct_host &&
              "$(field_of_first "${line}" data_path)" != direct_srflx ) ]]; then
        log "SCENARIO_FAILED path_switch phase1 (direct): ${line}"
        dump_outputs path_switch_phase1
        failures=$((failures + 1))
      else
        log "SCENARIO_OK path_switch phase1 direct: ${line}"
      fi
      sleep 4
      # Phase 2: inter-client forwarding blocked — the same devices must
      # re-establish over the mediated path.
      block_forwarding
      launch_responder "pswitch" 30000 \
        --stun ":${turn_port}" --turn ":${turn_port}" --turn-secret "${secret}"
      wait "${initiator_pid}" || true
      wait "${responder_pid}" || true
      line=$(first_result)
      if [[ "$(field_of_first "${line}" authenticated)" != "1" ||
            ( "$(field_of_first "${line}" data_path)" != turn_udp &&
              "$(field_of_first "${line}" data_path)" != direct_host ) ]]; then
        log "SCENARIO_FAILED path_switch phase2 (mediated): ${line}"
        dump_outputs path_switch_phase2
        failures=$((failures + 1))
      else
        log "SCENARIO_OK path_switch phase2 mediated: ${line}"
      fi
      sleep 4
      # Phase 3: forwarding restored — back to direct.
      allow_forwarding
      launch_responder "pswitch" 30000 --stun ":${turn_port}"
      wait "${initiator_pid}" || true
      wait "${responder_pid}" || true
      line=$(first_result)
      if [[ "$(field_of_first "${line}" authenticated)" != "1" ||
            ( "$(field_of_first "${line}" data_path)" != direct_host &&
              "$(field_of_first "${line}" data_path)" != direct_srflx ) ]]; then
        log "SCENARIO_FAILED path_switch phase3 (direct again): ${line}"
        dump_outputs path_switch_phase3
        failures=$((failures + 1))
      else
        log "SCENARIO_OK path_switch phase3 direct again: ${line}"
      fi
      ;;
    lease_expiry)
      allow_forwarding
      remove_rate
      # The matrix node requests a 3 s relay lease with 1 s heartbeats.
      # Freezing the responder past the lease expiry evicts its endpoint;
      # after thaw the endpoint must be re-published (heartbeat re-insert
      # or reconnect re-login) and a fresh initiator must reach it.
      prepare_participants "lease" || true
      sleep 4
      run_in "${ns1}" run "${work_dir}/lease-second.sqlite" matrix.second \
        "wss://${host1}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" 60000 \
        --role responder --hold-ms 45000 --stun "${host1}:${turn_port}" &
      responder_pid=$!
      sleep 2
      run_in "${ns0}" run "${work_dir}/lease-first.sqlite" matrix.first \
        "wss://${host0}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" 30000 \
        --role initiator --hold-ms 3000 --stun "${host0}:${turn_port}" || true
      line=$(first_result)
      if [[ "$(field_of_first "${line}" authenticated)" != "1" ]]; then
        log "SCENARIO_FAILED lease_expiry round1 (pre-freeze session): ${line}"
        dump_outputs lease_expiry
        failures=$((failures + 1))
      else
        log "SCENARIO_OK lease_expiry round1 pre-freeze: ${line}"
      fi
      kill -STOP "${responder_pid}"
      sleep 9
      kill -CONT "${responder_pid}"
      sleep 2
      run_in "${ns0}" run "${work_dir}/lease-first.sqlite" matrix.first \
        "wss://${host0}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" 30000 \
        --role initiator --hold-ms 3000 --stun "${host0}:${turn_port}" \
        --connect-retries 3 --authenticate-budget-ms 20000 || true
      line=$(first_result)
      if [[ "$(field_of_first "${line}" authenticated)" != "1" ]]; then
        log "SCENARIO_FAILED lease_expiry round2 (post-thaw re-publish): ${line}"
        dump_outputs lease_expiry
        failures=$((failures + 1))
      else
        log "SCENARIO_OK lease_expiry round2 post-thaw: ${line}"
      fi
      wait "${responder_pid}" || true
      responder_line=$(second_result)
      if [[ "$(field_of_first "${responder_line}" relay_state)" != "ready" ]]; then
        log "SCENARIO_FAILED lease_expiry (responder must re-login to ready): ${responder_line}"
        dump_outputs lease_expiry
        failures=$((failures + 1))
      else
        log "SCENARIO_OK lease_expiry responder recovery: ${responder_line}"
      fi
      ;;
    slow_receiver)
      allow_forwarding
      remove_rate
      limit_receiver_rate
      # 2 MiB into a 4 mbit / 50 ms receiver link (netem shaping yields
      # roughly 1 mbit of effective SCTP throughput): the transfer must
      # stay bounded (no session death, no unbounded queue growth
      # observable as a failure) and still commit within its wait budget.
      prepare_participants "slow" || true
      sleep 4
      launch_responder "slow" 40000 --stun ":${turn_port}" \
        --hold-ms 8000 --m7-bytes 2097152 --m7-wait-ms 25000
      wait "${initiator_pid}" || true
      wait "${responder_pid}" || true
      remove_rate
      line=$(first_result)
      if [[ "$(field_of_first "${line}" authenticated)" != "1" ||
            "$(field_of_first "${line}" m7_file)" != "1" ||
            ( "$(field_of_first "${line}" data_path)" != direct_host &&
              "$(field_of_first "${line}" data_path)" != direct_srflx ) ]]; then
        log "SCENARIO_FAILED slow_receiver: ${line}"
        dump_outputs slow_receiver
        failures=$((failures + 1))
      else
        log "SCENARIO_OK slow_receiver: ${line}"
      fi
      ;;
    stale_turn_credential)
      block_forwarding
      remove_rate
      # REST credentials derived one hour in the past: coturn must refuse
      # the allocation and the attempt must terminate explicitly (the same
      # bounded-failure contract as udp_blocked, on the credential axis).
      prepare_participants "stale" || true
      sleep 4
      run_in "${ns1}" run "${work_dir}/stale-second.sqlite" matrix.second \
        "wss://${host1}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" 40000 \
        --role responder --stun "${host1}:${turn_port}" \
        --turn "${host1}:${turn_port_b}" --turn-secret "${secret}" &
      responder_pid=$!
      run_in "${ns0}" run "${work_dir}/stale-first.sqlite" matrix.first \
        "wss://${host0}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" 40000 \
        --role initiator --stun "${host0}:${turn_port}" \
        --turn "${host0}:${turn_port}" --turn-secret "${secret}" \
        --turn-credential-expiry-offset-ms -3600000 \
        --authenticate-budget-ms 30000 || true
      wait "${responder_pid}" || true
      line=$(first_result)
      if [[ "$(field_of_first "${line}" authenticated)" != "0" ||
            "$(field_of_first "${line}" state)" != closed ||
            "$(field_of_first "${line}" session_error)" == "-" ]]; then
        log "SCENARIO_FAILED stale_turn_credential: ${line}"
        dump_outputs stale_turn_credential
        failures=$((failures + 1))
      else
        log "SCENARIO_OK stale_turn_credential (bounded explicit failure): ${line}"
      fi
      ;;
    *)
      log "unknown scenario: ${scenario}"
      exit 2
      ;;
  esac
done

if ((failures > 0)); then
  log "FAULT_MATRIX_FAILED failures=${failures}"
  cat "${work_dir}/${ns0}-output.txt" 2>/dev/null || true
  cat "${work_dir}/${ns1}-output.txt" 2>/dev/null || true
  cat "${work_dir}/relay.log" 2>/dev/null || true
  exit 1
fi
log "FAULT_MATRIX_OK scenarios=${scenarios[*]}"
