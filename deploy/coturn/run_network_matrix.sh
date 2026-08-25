#!/usr/bin/env bash
set -euo pipefail

# Heyaki M4 network-matrix harness (requires root, coturn, and the built apps):
# two isolated client namespaces + host coturn + host heyaki-relay, then the
# real heyaki-m4-matrix-node participants exercise the M4 connectivity matrix:
#   direct            inter-client forwarding allowed, STUN only
#   forced_turn       forwarding blocked, relay-only ICE policy
#   turn_fallback     forwarding blocked, automatic policy with STUN+TURN and
#                     a P95 budget for the TURN fallback (< 5 s exit gate)
#   udp_blocked       UDP to coturn blocked, TURN/UDP unavailable -> the
#                     attempt must terminate explicitly instead of hanging
#   lossy             100 ms / 10 % loss on both client links, forced TURN
#   relay_restart     relay WSS killed and restarted under an authenticated
#                     TURN session; the session must survive and re-login
# coturn always stays a separate process and is never embedded in the relay.

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
Scenarios: direct forced_turn turn_fallback udp_blocked lossy relay_restart
(default: all)
USAGE_EOF
}

log() { printf '[heyaki-m4-matrix] %s\n' "$*"; }
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
[[ -x "${matrix_bin}" ]] || skip "matrix node binary is unavailable: ${matrix_bin}"
[[ -x "${demo_bin}" ]] || skip "relay demo binary is unavailable: ${demo_bin}"
[[ $(id -u) -eq 0 ]] || skip "root privileges are required to create network namespaces"
ip netns add __heyaki_matrix_probe 2>/dev/null || skip "network namespace capability is unavailable"
ip netns delete __heyaki_matrix_probe
((${#scenarios[@]} == 0)) &&
  scenarios=(direct forced_turn turn_fallback udp_blocked lossy relay_restart)

work_dir=$(mktemp -d /tmp/heyaki-m4-matrix.XXXXXX)
chmod 700 "${work_dir}"
relay_pid=""
turn_pid=""
turn_pid_b=""
ns0="heyaki-m0"
ns1="heyaki-m1"
br0="heyaki-mb0"
br1="heyaki-mb1"
veth0="heyaki-mv0"
veth1="heyaki-mv1"
peer0="heyaki-mp0"
peer1="heyaki-mp1"
host0="10.78.0.1"
host1="10.78.1.1"
client0="10.78.0.10"
client1="10.78.1.10"
relay_port=8443
turn_port=3478
turn_port_b=3479
secret=$(openssl rand -base64 24)
tenant="matrix-tenant"
token="TEST-ONLY-m4-matrix-token-0123456789"

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
  iptables -D INPUT -i "${br0}" -p udp --dport "${turn_port}" -j DROP 2>/dev/null
  iptables -D INPUT -i "${br1}" -p udp --dport "${turn_port}" -j DROP 2>/dev/null
  ip netns delete "${ns0}" 2>/dev/null
  ip netns delete "${ns1}" 2>/dev/null
  ip link delete "${br0}" 2>/dev/null
  ip link delete "${br1}" 2>/dev/null
  rm -rf "${work_dir}"
}
trap cleanup EXIT

# ---- topology -----------------------------------------------------------
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
block_turn_udp() {
  iptables -I INPUT -i "${br0}" -p udp --dport "${turn_port}" -j DROP
  iptables -I INPUT -i "${br1}" -p udp --dport "${turn_port}" -j DROP
  iptables -I INPUT -i "${br0}" -p udp --dport "${turn_port_b}" -j DROP
  iptables -I INPUT -i "${br1}" -p udp --dport "${turn_port_b}" -j DROP
}
allow_turn_udp() {
  iptables -D INPUT -i "${br0}" -p udp --dport "${turn_port}" -j DROP 2>/dev/null || true
  iptables -D INPUT -i "${br1}" -p udp --dport "${turn_port}" -j DROP 2>/dev/null || true
  iptables -D INPUT -i "${br0}" -p udp --dport "${turn_port_b}" -j DROP 2>/dev/null || true
  iptables -D INPUT -i "${br1}" -p udp --dport "${turn_port_b}" -j DROP 2>/dev/null || true
}
add_loss() {
  tc qdisc add dev "${veth0}" root netem delay 100ms loss 10%
  tc qdisc add dev "${veth1}" root netem delay 100ms loss 10%
}
remove_loss() {
  tc qdisc del dev "${veth0}" root 2>/dev/null || true
  tc qdisc del dev "${veth1}" root 2>/dev/null || true
}

# ---- coturn and relay ---------------------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${work_dir}/turn-key.pem" -out "${work_dir}/turn-cert.pem" \
  -subj "/CN=heyaki-matrix-turn.invalid" -days 1 -set_serial 1 >/dev/null 2>&1
sed -e "s#__TURN_SECRET__#${secret}#" \
    -e "s#__ADVERTISED_ADDRESS__#${host0}#" \
    -e "s#__LISTEN_ADDRESS__#0.0.0.0#" \
    -e "s#/etc/letsencrypt/live/heyaki.invalid/fullchain.pem#${work_dir}/turn-cert.pem#" \
    -e "s#/etc/letsencrypt/live/heyaki.invalid/privkey.pem#${work_dir}/turn-key.pem#" \
    "${script_dir}/turnserver.conf" > "${work_dir}/turnserver.conf"
# The deploy baseline targets production abuse limits; the matrix topology
# runs many short-lived participants, and coturn RESERVES max-bps of
# bps-capacity per live allocation (the baseline budget admits only eight
# concurrent allocations, which the matrix exhausted with 486 errors). Raise
# the quotas and bandwidth budget; coturn cannot write /var/log/coturn in
# this sandbox, so keep session-level logs in the work dir.
printf 'log-file=%s/turn-a.log\nsimple-log\nVerbose\ntotal-quota=1000\nuser-quota=100\nmax-bps=10000000\nbps-capacity=100000000\n' "${work_dir}" \
  >> "${work_dir}/turnserver.conf"
# A second instance serves the other bridge: a relayed<->relayed candidate
# pair needs TWO TURN servers, because a single instance refuses peers on
# its own address.
sed -e "s#listening-port=${turn_port}#listening-port=${turn_port_b}#" \
    -e "s#min-port=49160#min-port=49180#" \
    -e "s#__ADVERTISED_ADDRESS__#${host1}#" \
    -e "s#log-file=${work_dir}/turn-a.log#log-file=${work_dir}/turn-b.log#" \
    "${work_dir}/turnserver.conf" > "${work_dir}/turnserver-b.conf"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -set_serial 1 \
  -subj "/CN=heyaki-matrix-relay" -keyout "${work_dir}/ca-key.pem" \
  -out "${work_dir}/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=${host0}" \
  -keyout "${work_dir}/relay-key.pem" -out "${work_dir}/relay.csr" >/dev/null 2>&1
printf 'subjectAltName=IP:%s,IP:%s\n' "${host0}" "${host1}" > "${work_dir}/san.ext"
openssl x509 -req -in "${work_dir}/relay.csr" -CA "${work_dir}/ca.pem" \
  -CAkey "${work_dir}/ca-key.pem" -CAcreateserial -days 1 \
  -extfile "${work_dir}/san.ext" -out "${work_dir}/relay-cert.pem" >/dev/null 2>&1

expiry=$(python3 -c 'import time; print(int(time.time() * 1000) + 3600000)')
# Every scenario enrolls two fresh participants; the token must cover all of
# them or every scenario after the first exhausts it and reports relay=failed.
"${demo_bin}" seed-token "${work_dir}/relay.sqlite" "${tenant}" "${token}" "${expiry}" 64

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
    >"${work_dir}/relay.log" 2>&1 &
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
  [[ -n "${relay_pid}" ]] && kill -TERM "${relay_pid}" 2>/dev/null
  sleep 0.3
  [[ -n "${relay_pid}" ]] && kill -KILL "${relay_pid}" 2>/dev/null
  relay_pid=""
}

"${coturn_bin}" -c "${work_dir}/turnserver.conf" >"${work_dir}/turn-a-stdout.log" 2>&1 &
turn_pid=$!
"${coturn_bin}" -c "${work_dir}/turnserver-b.conf" >"${work_dir}/turn-b-stdout.log" 2>&1 &
turn_pid_b=$!
start_relay

for namespace in "${ns0}" "${ns1}"; do
  ip netns exec "${namespace}" bash -c "exec 3<>/dev/tcp/127.0.0.1/1" 2>/dev/null || true
done
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

# Scenario arguments are side-agnostic: --stun/--turn take a ":PORT" form and
# are expanded per side to that bridge's host address, with the TURN server of
# the initiator on turn A and of the responder on turn B (a relayed<->relayed
# candidate pair needs two distinct TURN servers).
run_pair() {
  local tag=$1 budget=$2; shift 2
  prepare_participants "${tag}"
  # Let endpoints from the previous scenario fall out of the relay directory
  # (3 s presence lease) so the initiator cannot dial a stale endpoint.
  sleep 4
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
    # Initiator allocates on turn A; responder on turn B so a forced
    # relayed<->relayed pair crosses two distinct TURN servers.
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
  local responder_pid=$!
  run_in "${ns0}" run "${work_dir}/${tag}-first.sqlite" matrix.first \
    "wss://${host0}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" "${budget}" \
    --role initiator ${initiator_args[@]+"${initiator_args[@]}"}
  local initiator_status=$?
  wait "${responder_pid}" || true
  return "${initiator_status}"
}

failures=0
dump_outputs() {
  local scenario=$1
  log "OUTPUTS ${scenario} ns0:"
  sed -n '1,12p' "${work_dir}/${ns0}-output.txt" 2>/dev/null || true
  log "OUTPUTS ${scenario} ns1:"
  sed -n '1,12p' "${work_dir}/${ns1}-output.txt" 2>/dev/null || true
  log "RELAY_LOG ${scenario}:"
  tail -n 12 "${work_dir}/relay.log" 2>/dev/null || true
  log "TURN_LOG ${scenario}:"
  for turn_log_name in turn-a.log turn-b.log; do
    grep -E "session [0-9]|allocated|error [0-9]+|quota" \
      "${work_dir}/${turn_log_name}" 2>/dev/null | tail -n 30 || true
  done
}
require_authenticated_turn() {
  local line=$1 scenario=$2
  local authenticated data_path
  authenticated=$(result_field "${line}" authenticated)
  data_path=$(result_field "${line}" data_path)
  if [[ "${authenticated}" != "1" || "${data_path}" != turn_udp ]]; then
    log "SCENARIO_FAILED ${scenario}: ${line}"
    failures=$((failures + 1))
    return 1
  fi
  log "SCENARIO_OK ${scenario}: ${line}"
}

for scenario in "${scenarios[@]}"; do
  case "${scenario}" in
    direct)
      allow_forwarding
      remove_loss
      run_pair "direct" 30000 --stun ":${turn_port}" \
        || failures=$((failures + 1))
      line=$(first_result)
      authenticated=$(result_field "${line}" authenticated)
      data_path=$(result_field "${line}" data_path)
      if [[ "${authenticated}" != "1" ||
            "${data_path}" != direct_host && "${data_path}" != direct_srflx ]]; then
        log "SCENARIO_FAILED direct: ${line}"
        dump_outputs direct
        failures=$((failures + 1))
      else
        log "SCENARIO_OK direct: ${line}"
      fi
      ;;
    forced_turn)
      block_forwarding
      remove_loss
      run_pair "forced" 30000 --turn ":${turn_port}" \
        --turn-secret "${secret}" --force-turn || failures=$((failures + 1))
      require_authenticated_turn "$(first_result)" forced_turn || true
      require_authenticated_turn "$(second_result)" forced_turn_responder || true
      ;;
    turn_fallback)
      block_forwarding
      remove_loss
      samples=()
      for cycle in $(seq 1 6); do
        run_pair "fallback-${cycle}" 30000 \
          --stun ":${turn_port}" \
          --turn ":${turn_port}" --turn-secret "${secret}" \
          || failures=$((failures + 1))
        line=$(first_result)
        require_authenticated_turn "${line}" "turn_fallback_cycle${cycle}" || true
        duration=$(result_field "${line}" duration_ms)
        [[ -n "${duration}" ]] && samples+=("${duration}")
      done
      if ((${#samples[@]} == 6)); then
        p95=$(printf '%s\n' "${samples[@]}" | sort -n | sed -n '6p')
        log "TURN_FALLBACK_P95_MS ${p95}"
        if ((p95 >= 5000)); then
          log "SCENARIO_FAILED turn_fallback: p95 ${p95}ms exceeds 5000ms"
          dump_outputs turn_fallback
          failures=$((failures + 1))
        fi
      else
        log "SCENARIO_FAILED turn_fallback: missing samples"
        dump_outputs turn_fallback
        failures=$((failures + 1))
      fi
      ;;
    udp_blocked)
      block_forwarding
      remove_loss
      block_turn_udp
      run_pair "udp-blocked" 40000 \
        --stun ":${turn_port}" \
        --turn ":${turn_port}" --turn-secret "${secret}" \
        --authenticate-budget-ms 30000 || failures=$((failures + 1))
      line=$(first_result)
      authenticated=$(result_field "${line}" authenticated)
      if [[ "${authenticated}" != "0" ]]; then
        log "SCENARIO_FAILED udp_blocked: unexpected session ${line}"
        dump_outputs udp_blocked
        failures=$((failures + 1))
      else
        log "SCENARIO_OK udp_blocked (bounded explicit failure): ${line}"
      fi
      allow_turn_udp
      ;;
    lossy)
      block_forwarding
      add_loss
      run_pair "lossy" 90000 --turn ":${turn_port}" \
        --turn-secret "${secret}" --force-turn --connect-retries 5 \
        --authenticate-budget-ms 75000 || failures=$((failures + 1))
      require_authenticated_turn "$(first_result)" lossy || true
      remove_loss
      ;;
    relay_restart)
      block_forwarding
      remove_loss
      prepare_participants "restart" || {
        dump_outputs relay_restart
        failures=$((failures + 1))
        continue
      }
      sleep 4
      run_in "${ns1}" run "${work_dir}/restart-second.sqlite" matrix.second \
        "wss://${host1}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" 30000 \
        --role responder --turn "${host1}:${turn_port_b}" \
        --turn-secret "${secret}" --force-turn --hold-ms 10000 &
      responder_pid=$!
      run_in "${ns0}" run "${work_dir}/restart-first.sqlite" matrix.first \
        "wss://${host0}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" 30000 \
        --role initiator --turn "${host0}:${turn_port}" \
        --turn-secret "${secret}" --force-turn --hold-ms 10000 &
      initiator_pid=$!
      sleep 8
      stop_relay
      sleep 2
      start_relay || failures=$((failures + 1))
      wait "${initiator_pid}" || failures=$((failures + 1))
      wait "${responder_pid}" || true
      line=$(first_result)
      authenticated=$(result_field "${line}" authenticated)
      relay_state=$(result_field "${line}" relay_state)
      if [[ "${authenticated}" != "1" || "${relay_state}" != ready ]]; then
        log "SCENARIO_FAILED relay_restart: ${line}"
        dump_outputs relay_restart
        failures=$((failures + 1))
      else
        log "SCENARIO_OK relay_restart: ${line}"
      fi
      ;;
    *)
      log "unknown scenario: ${scenario}"
      exit 2
      ;;
  esac
done

if ((failures > 0)); then
  log "MATRIX_FAILED failures=${failures}"
  cat "${work_dir}/${ns0}-output.txt" 2>/dev/null || true
  cat "${work_dir}/${ns1}-output.txt" 2>/dev/null || true
  cat "${work_dir}/relay.log" 2>/dev/null || true
  exit 1
fi
log "MATRIX_OK scenarios=${scenarios[*]}"
