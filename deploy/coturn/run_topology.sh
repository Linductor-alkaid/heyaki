#!/usr/bin/env bash
set -euo pipefail

# Heyaki M3B-13 local one-click topology:
# two isolated client network namespaces + host relay + host coturn.
# coturn is always a separate process and is never embedded in heyaki-relay.

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/../.." && pwd)
relay_bin=${HEYAKI_RELAY_BIN:-"${repo_root}/build/heyaki-relay"}
coturn_bin=${HEYAKI_COTURN_BIN:-}
check_only=false
keep=false

usage() {
  cat <<USAGE_EOF
Usage: $0 [--relay-bin PATH] [--coturn-bin PATH] [--check-only] [--keep]

Creates two isolated client namespaces, starts host coturn and heyaki-relay,
runs reachability checks from both namespaces, then tears the topology down.
Use --check-only to verify prerequisites without changing host state.
USAGE_EOF
}

log() { printf '[heyaki-turn-topology] %s\n' "$*"; }
skip() { printf 'SKIP: %s\n' "$*"; exit 77; }

while (($# > 0)); do
  case "$1" in
    --relay-bin) relay_bin=${2:?missing relay-bin value}; shift 2;;
    --coturn-bin) coturn_bin=${2:?missing coturn-bin value}; shift 2;;
    --check-only) check_only=true; shift;;
    --keep) keep=true; shift;;
    -h|--help) usage; exit 0;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 2;;
  esac
done

for command_name in ip iptables openssl; do
  command -v "${command_name}" >/dev/null 2>&1 || skip "${command_name} is unavailable"
done
if [[ -z "${coturn_bin}" ]]; then
  coturn_bin=$(command -v turnserver || true)
fi
[[ -n "${coturn_bin}" ]] || skip "turnserver is unavailable; install coturn or pass --coturn-bin"
if [[ "${check_only}" == "true" ]]; then
  [[ -x "${relay_bin}" ]] || skip "relay binary is unavailable: ${relay_bin}"
  [[ -x "${coturn_bin}" ]] || skip "coturn binary is unavailable: ${coturn_bin}"
  log "TOPOLOGY_CHECK_OK relay=${relay_bin} coturn=${coturn_bin}"
  exit 0
fi

if [[ $(id -u) -ne 0 ]]; then
  skip "root privileges are required to create network namespaces"
fi
ip netns add __heyaki_topology_probe 2>/dev/null || skip "network namespace capability is unavailable"
ip netns delete __heyaki_topology_probe

work_dir=$(mktemp -d)
relay_pid=""
turn_pid=""
ns0="heyaki-t0"
ns1="heyaki-t1"
br0="heyaki-br0"
br1="heyaki-br1"
veth0="heyaki-v0"
veth1="heyaki-v1"
peer0="heyaki-p0"
peer1="heyaki-p1"
host0="10.77.0.1"
host1="10.77.1.1"
client0="10.77.0.10"
client1="10.77.1.10"
relay_port=8443

cleanup() {
  set +e
  [[ -n "${relay_pid}" ]] && kill -TERM "${relay_pid}" 2>/dev/null
  [[ -n "${turn_pid}" ]] && kill -TERM "${turn_pid}" 2>/dev/null
  sleep 0.2
  [[ -n "${relay_pid}" ]] && kill -KILL "${relay_pid}" 2>/dev/null
  [[ -n "${turn_pid}" ]] && kill -KILL "${turn_pid}" 2>/dev/null
  iptables -D FORWARD -s "${client0}" -d "${client1}" -j DROP 2>/dev/null
  iptables -D FORWARD -s "${client1}" -d "${client0}" -j DROP 2>/dev/null
  ip netns delete "${ns0}" 2>/dev/null
  ip netns delete "${ns1}" 2>/dev/null
  ip link delete "${br0}" 2>/dev/null
  ip link delete "${br1}" 2>/dev/null
  if [[ "${keep}" != "true" ]]; then
    rm -rf "${work_dir}"
  else
    log "artifacts kept in ${work_dir}"
  fi
}
trap cleanup EXIT

secret=$(openssl rand -base64 24)
advertised_address=${HEYAKI_TURN_ADVERTISED_ADDRESS:-"${host0}"}
listen_address=${HEYAKI_TURN_LISTEN_ADDRESS:-"0.0.0.0"}

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${work_dir}/turn-key.pem" \
  -out "${work_dir}/turn-cert.pem" \
  -subj "/CN=heyaki-turn.invalid" -days 1 -set_serial 1 >/dev/null 2>&1
cp "${work_dir}/turn-cert.pem" "${work_dir}/relay-cert.pem"
cp "${work_dir}/turn-key.pem" "${work_dir}/relay-key.pem"

sed -e "s#__TURN_SECRET__#${secret}#" \
    -e "s#__ADVERTISED_ADDRESS__#${advertised_address}#" \
    -e "s#__LISTEN_ADDRESS__#${listen_address}#" \
    -e "s#/etc/letsencrypt/live/heyaki.invalid/fullchain.pem#${work_dir}/turn-cert.pem#" \
    -e "s#/etc/letsencrypt/live/heyaki.invalid/privkey.pem#${work_dir}/turn-key.pem#" \
    "${script_dir}/turnserver.conf" > "${work_dir}/turnserver.conf"

cat > "${work_dir}/relay.conf" <<RELAY_EOF
listen_address = 0.0.0.0
listen_port = ${relay_port}
tls_certificate_file = ${work_dir}/relay-cert.pem
tls_private_key_file = ${work_dir}/relay-key.pem
database_file = ${work_dir}/relay.sqlite
handshake_timeout_milliseconds = 2000
shutdown_timeout_milliseconds = 2000
RELAY_EOF

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

iptables -I FORWARD -s "${client0}" -d "${client1}" -j DROP
iptables -I FORWARD -s "${client1}" -d "${client0}" -j DROP

"${coturn_bin}" -c "${work_dir}/turnserver.conf" >"${work_dir}/turn.log" 2>&1 &
turn_pid=$!
"${relay_bin}" --config "${work_dir}/relay.conf" >"${work_dir}/relay.log" 2>&1 &
relay_pid=$!

wait_for_port() {
  local namespace=$1 address=$2 port=$3
  for _ in $(seq 1 100); do
    if ip netns exec "${namespace}" bash -c "exec 3<>/dev/tcp/${address}/${port}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_for_port "${ns0}" "${host0}" 3478
wait_for_port "${ns1}" "${host1}" 3478
wait_for_port "${ns0}" "${host0}" "${relay_port}"
wait_for_port "${ns1}" "${host1}" "${relay_port}"

if ! ip netns exec "${ns0}" turnutils_stunclient "${host0}" >"${work_dir}/stun0.log" 2>&1; then
  log "STUN check failed in namespace ${ns0}"
  cat "${work_dir}/stun0.log"
  exit 1
fi
if ! ip netns exec "${ns1}" turnutils_stunclient "${host1}" >"${work_dir}/stun1.log" 2>&1; then
  log "STUN check failed in namespace ${ns1}"
  cat "${work_dir}/stun1.log"
  exit 1
fi

if ! ip netns exec "${ns0}" ping -c1 -W1 "${client1}" >/dev/null 2>&1; then
  log "inter-client forwarding is blocked"
else
  log "ERROR: inter-client forwarding is not blocked"
  exit 1
fi

log "TOPOLOGY_OK relay=${relay_port} turn=3478 clients=${client0},${client1}"
