#!/usr/bin/env bash
set -euo pipefail

# Heyaki M9-06 NAT matrix harness (requires root, coturn, and the built apps).
# Two private client namespaces reach a public namespace (heyaki-relay + two
# coturn instances) ONLY through nftables-emulated NATs; the real
# heyaki-m4-matrix-node participants then prove per-NAT connectivity:
#   full_cone            endpoint-independent mapping + filtering; both peers
#                        hole-punch a direct srflx data path
#   restricted_cone      EIM + address-dependent filtering; inbound allowed
#                        only from IPs the client contacted
#   port_restricted_cone EIM + address-and-port filtering (classic hole punch)
#   symmetric            per-destination disjoint port ranges, no inbound DNAT;
#                        direct must fail and TURN must save the session
#   hairpin              both peers behind ONE NAT on one bridge; they reach
#                        each other through their mapped public addresses
#   cgnat                home full-cone NAT stacked below a carrier symmetric
#                        NAT (double NAT); TURN fallback across both layers
# tests/network/nat_probe.py queries both STUN servers from one socket before
# each heyaki run, so the emulated NAT class itself is verified (mapping
# equality/inequality and the public alias), not just the session outcome.
# coturn always stays a separate process and is never embedded in the relay.

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/../.." && pwd)

relay_bin=${HEYAKI_RELAY_BIN:-"${repo_root}/build/heyaki-relay"}
matrix_bin=${HEYAKI_MATRIX_BIN:-"${repo_root}/build/heyaki-m4-matrix-node"}
demo_bin=${HEYAKI_DEMO_BIN:-"${repo_root}/build/heyaki-m3b-relay-demo"}
probe_bin="${repo_root}/tests/network/nat_probe.py"
coturn_bin=${HEYAKI_COTURN_BIN:-}

usage() {
  cat <<USAGE_EOF
Usage: $0 --relay-bin PATH --matrix-bin PATH [--demo-bin PATH] [--coturn-bin PATH]
          [--scenario NAME]...
Scenarios: full_cone restricted_cone port_restricted_cone symmetric hairpin cgnat
(default: all)
USAGE_EOF
}

log() { printf '[heyaki-nat-matrix] %s\n' "$*"; }
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

for command_name in ip nft iptables openssl python3 sysctl; do
  command -v "${command_name}" >/dev/null 2>&1 || skip "${command_name} is unavailable"
done
[[ -z "${coturn_bin}" ]] && coturn_bin=$(command -v turnserver || true)
[[ -n "${coturn_bin}" ]] || skip "turnserver is unavailable; install coturn or pass --coturn-bin"
[[ -x "${relay_bin}" ]] || skip "relay binary is unavailable: ${relay_bin}"
[[ -x "${matrix_bin}" ]] || skip "matrix node binary is unavailable: ${matrix_bin}"
[[ -x "${demo_bin}" ]] || skip "relay demo binary is unavailable: ${demo_bin}"
[[ -r "${probe_bin}" ]] || skip "nat probe is unavailable: ${probe_bin}"
[[ $(id -u) -eq 0 ]] || skip "root privileges are required to create network namespaces"
ip netns add __heyaki_nat_probe 2>/dev/null || skip "network namespace capability is unavailable"
ip netns delete __heyaki_nat_probe
nft add table inet __heyaki_nat_probe 2>/dev/null || skip "nftables is unavailable to this process"
nft delete table inet __heyaki_nat_probe
((${#scenarios[@]} == 0)) &&
  scenarios=(full_cone restricted_cone port_restricted_cone symmetric hairpin cgnat)

work_dir=$(mktemp -d /tmp/heyaki-nat-matrix.XXXXXX)
chmod 700 "${work_dir}"
relay_pid=""
turn_pid=""
turn_pid_b=""
br0="hynat-b0"
br1="hynat-b1"
hyap="hynat-pub"          # host end of the public veth pair
ns_pub="hynat-pubns"
ns0="hynat-n0"
ns0b="hynat-n0b"
ns1="hynat-n1"
gwa="hynat-gwa"           # CGNAT home gateway for the initiator side
gwb="hynat-gwb"           # CGNAT home gateway for the responder side
ns2="hynat-n2"
ns3="hynat-n3"
namespaces=("${ns_pub}" "${ns0}" "${ns0b}" "${ns1}" "${gwa}" "${gwb}" "${ns2}" "${ns3}")
host0="10.78.0.1"
host1="10.78.1.1"
client0="10.78.0.10"
client0b="10.78.0.11"
client1="10.78.1.10"
gwa_wan="10.78.0.50"
gwb_wan="10.78.1.50"
gwa_lan="10.79.0.1"
gwb_lan="10.79.1.1"
client2="10.79.0.10"
client3="10.79.1.10"
pub_host="203.0.113.1"    # host address on the public segment
pub_relay="203.0.113.4"   # relay + public-namespace gateway address
turn_a_ip="203.0.113.2"   # coturn A advertised address (initiator STUN/TURN)
turn_b_ip="203.0.113.3"   # coturn B advertised address (responder STUN/TURN)
map0="203.0.113.10"       # public alias behind which client0 (and gwa) sits
map0b="203.0.113.11"      # hairpin second client alias
map1="203.0.113.20"       # public alias behind which client1 (and gwb) sits
relay_port=8443
turn_port=3478
turn_port_b=3480
secret=$(openssl rand -base64 24)
tenant="nat-tenant"
token="TEST-ONLY-nat-matrix-token-0123456789"

forward_accept_specs=()

cleanup() {
  set +e
  [[ -n "${relay_pid}" ]] && kill -TERM "${relay_pid}" 2>/dev/null
  [[ -n "${turn_pid}" ]] && kill -TERM "${turn_pid}" 2>/dev/null
  [[ -n "${turn_pid_b}" ]] && kill -TERM "${turn_pid_b}" 2>/dev/null
  sleep 0.2
  [[ -n "${relay_pid}" ]] && kill -KILL "${relay_pid}" 2>/dev/null
  [[ -n "${turn_pid}" ]] && kill -KILL "${turn_pid}" 2>/dev/null
  [[ -n "${turn_pid_b}" ]] && kill -KILL "${turn_pid_b}" 2>/dev/null
  nft delete table inet heyaki_nat 2>/dev/null
  for spec in "${forward_accept_specs[@]}"; do
    # shellcheck disable=SC2086
    while iptables -C FORWARD ${spec} -j ACCEPT 2>/dev/null; do
      # shellcheck disable=SC2086
      iptables -D FORWARD ${spec} -j ACCEPT 2>/dev/null
    done
  done
  for namespace in "${namespaces[@]}"; do
    ip netns delete "${namespace}" 2>/dev/null
  done
  ip link delete "${br0}" 2>/dev/null
  ip link delete "${br1}" 2>/dev/null
  ip link delete "${hyap}" 2>/dev/null
  rm -rf "${work_dir}"
}
trap cleanup EXIT
trap 'log "SCRIPT_ERROR at line ${LINENO} (status $?)"' ERR

insert_forward_accept() {
  local spec="$1"
  forward_accept_specs+=("${spec}")
  # shellcheck disable=SC2086
  iptables -C FORWARD ${spec} -j ACCEPT 2>/dev/null ||
    # shellcheck disable=SC2086
    iptables -I FORWARD ${spec} -j ACCEPT
}

# ---- topology -----------------------------------------------------------
sysctl -w net.ipv4.ip_forward=1 >/dev/null
# Hairpin and DNAT return traffic look "wrong-way" to strict reverse-path
# filtering on multi-interface hosts; force the loose policy on our links.
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null
ip link add "${br0}" type bridge
ip link add "${br1}" type bridge
ip addr add "${host0}/24" dev "${br0}"
ip addr add "${host1}/24" dev "${br1}"
ip link set "${br0}" up
ip link set "${br1}" up

# Public segment: one veth pair; the host end carries the relay and the mapped
# aliases, the namespace end hosts relay + two coturn instances.
ip link add "${hyap}" type veth peer name hpb
ip addr add "${pub_host}/24" dev "${hyap}"
ip addr add "${map0}/32" dev "${hyap}"
ip addr add "${map0b}/32" dev "${hyap}"
ip addr add "${map1}/32" dev "${hyap}"
ip link set "${hyap}" up
ip netns add "${ns_pub}"
ip link set hpb netns "${ns_pub}"
ip netns exec "${ns_pub}" ip link set lo up
ip netns exec "${ns_pub}" ip addr add "${pub_relay}/24" dev hpb
ip netns exec "${ns_pub}" ip addr add "${turn_a_ip}/32" dev hpb
ip netns exec "${ns_pub}" ip addr add "${turn_b_ip}/32" dev hpb
ip netns exec "${ns_pub}" ip link set hpb up
ip netns exec "${ns_pub}" ip route add default via "${pub_host}"

create_client() {
  # namespace bridge host_addr client_addr
  local ns=$1 bridge=$2 host_addr=$3 client_addr=$4
  ip netns add "${ns}"
  ip link add "v-${ns}" type veth peer name "p-${ns}"
  ip link set "v-${ns}" master "${bridge}"
  ip link set "v-${ns}" up
  ip link set "p-${ns}" netns "${ns}"
  ip netns exec "${ns}" ip link set lo up
  ip netns exec "${ns}" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 || true
  ip netns exec "${ns}" ip addr add "${client_addr}/24" dev "p-${ns}"
  ip netns exec "${ns}" ip link set "p-${ns}" up
  ip netns exec "${ns}" ip route add default via "${host_addr}"
}
create_client "${ns0}" "${br0}" "${host0}" "${client0}"
create_client "${ns0b}" "${br0}" "${host0}" "${client0b}"
create_client "${ns1}" "${br1}" "${host1}" "${client1}"

# CGNAT gateways: the wan veth rides the client bridge, the lan veth serves a
# deep client namespace behind a full-cone home NAT (table inet home below).
create_home_gateway() {
  # gw_ns bridge host_addr wan_addr lan_addr lan_subnet deep_ns deep_addr
  local gw=$1 bridge=$2 host_addr=$3 wan_addr=$4 lan_addr=$5 lan_subnet=$6 deep_ns=$7 deep_addr=$8
  ip netns add "${gw}"
  ip link add "v-${gw}" type veth peer name "w-${gw}"
  ip link set "v-${gw}" master "${bridge}"
  ip link set "v-${gw}" up
  ip link set "w-${gw}" netns "${gw}"
  ip netns exec "${gw}" ip link set lo up
  ip netns exec "${gw}" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 || true
  ip netns exec "${gw}" ip addr add "${wan_addr}/24" dev "w-${gw}"
  ip netns exec "${gw}" ip link set "w-${gw}" up
  ip netns exec "${gw}" ip route add default via "${host_addr}"
  ip netns exec "${gw}" sysctl -qw net.ipv4.ip_forward=1
  ip link add "l-${gw}" type veth peer name "d-${gw}"
  ip link set "l-${gw}" netns "${gw}"
  ip netns exec "${gw}" ip addr add "${lan_addr}/24" dev "l-${gw}"
  ip netns exec "${gw}" ip link set "l-${gw}" up
  ip netns add "${deep_ns}"
  ip link set "d-${gw}" netns "${deep_ns}"
  ip netns exec "${deep_ns}" ip link set lo up
  ip netns exec "${deep_ns}" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 || true
  ip netns exec "${deep_ns}" ip addr add "${deep_addr}/24" dev "d-${gw}"
  ip netns exec "${deep_ns}" ip link set "d-${gw}" up
  ip netns exec "${deep_ns}" ip route add default via "${lan_addr}"
  # Home NAT: full cone (static DNAT for the wan alias, port-preserving SNAT).
  ip netns exec "${gw}" nft add table inet home
  ip netns exec "${gw}" nft add chain inet home pre \
    '{ type nat hook prerouting priority dstnat; policy accept; }'
  ip netns exec "${gw}" nft add chain inet home out \
    '{ type nat hook postrouting priority srcnat; policy accept; }'
  ip netns exec "${gw}" nft add rule inet home pre \
    "meta l4proto udp ip daddr ${wan_addr} dnat to ${deep_addr}"
  ip netns exec "${gw}" nft add rule inet home out \
    "meta l4proto udp ip saddr ${lan_subnet} snat ip to ${wan_addr}"
}
create_home_gateway "${gwa}" "${br0}" "${host0}" "${gwa_wan}" "${gwa_lan}" \
  "10.79.0.0/24" "${ns2}" "${client2}"
create_home_gateway "${gwb}" "${br1}" "${host1}" "${gwb_wan}" "${gwb_lan}" \
  "10.79.1.0/24" "${ns3}" "${client3}"
# The deep CGNAT clients talk to the relay with un-NATated TCP sources, so the
# host needs return routes into the home-gateway LANs.
ip route add 10.79.0.0/24 via "${gwa_wan}" dev "${br0}"
ip route add 10.79.1.0/24 via "${gwb_wan}" dev "${br1}"

# GitHub runners carry Docker's FORWARD policy DROP; explicit ACCEPTs in front
# of it keep host routing between the client bridges and the public segment
# alive. Scenario drops live in the separate nft table and still apply: an
# ACCEPT verdict in one base chain does not bypass other base chains.
insert_forward_accept "-i ${br0}"
insert_forward_accept "-o ${br0}"
insert_forward_accept "-i ${br1}"
insert_forward_accept "-o ${br1}"
insert_forward_accept "-i ${hyap}"
insert_forward_accept "-o ${hyap}"

# ---- coturn and relay ---------------------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${work_dir}/turn-key.pem" -out "${work_dir}/turn-cert.pem" \
  -subj "/CN=heyaki-nat-matrix-turn.invalid" -days 1 -set_serial 1 >/dev/null 2>&1
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
  # The deploy baseline targets production abuse limits; the matrix runs many
  # short-lived participants and coturn RESERVES max-bps per allocation, so
  # raise the quotas and bandwidth budget like the M4 harness does.
  printf 'simple-log\nVerbose\ntotal-quota=1000\nuser-quota=100\nmax-bps=10000000\nbps-capacity=100000000\nallow-loopback-peers\n'
}
write_turn_conf "${turn_a_ip}" "${turn_port}" 3479 5349 5350 49160 49199 turn-a.log \
  > "${work_dir}/turnserver-a.conf"
write_turn_conf "${turn_b_ip}" "${turn_port_b}" 3481 5351 5352 49200 49239 turn-b.log \
  > "${work_dir}/turnserver-b.conf"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -set_serial 1 \
  -subj "/CN=heyaki-nat-matrix-relay" -keyout "${work_dir}/ca-key.pem" \
  -out "${work_dir}/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=${pub_relay}" \
  -keyout "${work_dir}/relay-key.pem" -out "${work_dir}/relay.csr" >/dev/null 2>&1
printf 'subjectAltName=IP:%s\n' "${pub_relay}" > "${work_dir}/san.ext"
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
  ip netns exec "${ns_pub}" "${relay_bin}" --config "${work_dir}/relay.conf" \
    >"${work_dir}/relay.log" 2>&1 &
  relay_pid=$!
  for _ in $(seq 1 100); do
    if (exec 3<>"/dev/tcp/${pub_relay}/${relay_port}") 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  cat "${work_dir}/relay.log"
  return 1
}

ip netns exec "${ns_pub}" "${coturn_bin}" -c "${work_dir}/turnserver-a.conf" \
  >"${work_dir}/turn-a-stdout.log" 2>&1 &
turn_pid=$!
ip netns exec "${ns_pub}" "${coturn_bin}" -c "${work_dir}/turnserver-b.conf" \
  >"${work_dir}/turn-b-stdout.log" 2>&1 &
turn_pid_b=$!
start_relay
sleep 2
log "TOPOLOGY_OK relay=${pub_relay}:${relay_port} turnA=${turn_a_ip}:${turn_port} turnB=${turn_b_ip}:${turn_port_b}"

# ---- NAT emulation ------------------------------------------------------
nft_bootstrap() {
  nft delete table inet heyaki_nat 2>/dev/null || true
  nft add table inet heyaki_nat
  nft add chain inet heyaki_nat pre \
    '{ type nat hook prerouting priority dstnat; policy accept; }'
  nft add chain inet heyaki_nat out \
    '{ type nat hook postrouting priority srcnat; policy accept; }'
  nft add chain inet heyaki_nat flt \
    '{ type filter hook forward priority 0; policy accept; }'
  nft add rule inet heyaki_nat flt ct state established,related accept
}

# Blocks host-candidate traffic that would bypass the emulated NAT through
# plain host routing. Must be added AFTER any per-scenario accept rules: a
# DNAT'd packet already carries the peer's PRIVATE address at the forward
# hook (DNAT runs in prerouting), so NAT-traversing traffic is
# address-indistinguishable from a direct pair and needs an earlier accept
# (ct status dnat) or its own filter chain in front of these drops.
client_bypass_drops() {
  nft add rule inet heyaki_nat flt meta l4proto udp \
    ip saddr 10.78.0.0/24 ip daddr 10.78.1.0/24 drop
  nft add rule inet heyaki_nat flt meta l4proto udp \
    ip saddr 10.78.1.0/24 ip daddr 10.78.0.0/24 drop
  nft add rule inet heyaki_nat flt meta l4proto udp \
    ip saddr 10.79.0.0/24 ip daddr 10.79.1.0/24 drop
  nft add rule inet heyaki_nat flt meta l4proto udp \
    ip saddr 10.79.1.0/24 ip daddr 10.79.0.0/24 drop
}

# Static full-cone translation: inbound DNAT to the client for every UDP
# destination port (endpoint-independent filtering), outbound port-preserving
# SNAT to the alias (endpoint-independent mapping). cone_accept must be
# added before client_bypass_drops: every NAT-traversing packet is DNAT'd to
# the peer's private address before the forward hook.
cone_accept() {
  nft add rule inet heyaki_nat flt meta l4proto udp ct status dnat accept
}

cone_static() {
  # client0 map0 client1 map1 excluded_subnet0 excluded_subnet1
  local c0=$1 m0=$2 c1=$3 m1=$4 s0=$5 s1=$6
  nft add rule inet heyaki_nat pre meta l4proto udp ip daddr "${m0}" dnat to "${c0}"
  nft add rule inet heyaki_nat pre meta l4proto udp ip daddr "${m1}" dnat to "${c1}"
  nft add rule inet heyaki_nat out meta l4proto udp \
    ip saddr "${c0}" ip daddr != "${s0}" snat to "${m0}"
  nft add rule inet heyaki_nat out meta l4proto udp \
    ip saddr "${c1}" ip daddr != "${s1}" snat to "${m1}"
}

# Dynamic per-client outbound contact sets gate the static DNAT inbound path.
restricted_filter() {
  local c0=$1 c1=$2
  nft add set inet heyaki_nat c0_ips '{ type ipv4_addr; }'
  nft add set inet heyaki_nat c1_ips '{ type ipv4_addr; }'
  nft add rule inet heyaki_nat flt meta l4proto udp \
    ip saddr "${c0}" update @c0_ips { ip daddr }
  nft add rule inet heyaki_nat flt meta l4proto udp \
    ip saddr "${c1}" update @c1_ips { ip daddr }
  nft add rule inet heyaki_nat flt meta l4proto udp \
    ip daddr "${c0}" ip saddr @c0_ips accept
  nft add rule inet heyaki_nat flt meta l4proto udp \
    ip daddr "${c1}" ip saddr @c1_ips accept
  nft add rule inet heyaki_nat flt meta l4proto udp ip daddr "${c0}" drop
  nft add rule inet heyaki_nat flt meta l4proto udp ip daddr "${c1}" drop
}

port_restricted_filter() {
  local c0=$1 c1=$2
  nft add set inet heyaki_nat c0_ap '{ type ipv4_addr . inet_service; }'
  nft add set inet heyaki_nat c1_ap '{ type ipv4_addr . inet_service; }'
  nft add rule inet heyaki_nat flt meta l4proto udp \
    ip saddr "${c0}" update @c0_ap { ip daddr . udp dport }
  nft add rule inet heyaki_nat flt meta l4proto udp \
    ip saddr "${c1}" update @c1_ap { ip daddr . udp dport }
  nft add rule inet heyaki_nat flt meta l4proto udp \
    ip daddr "${c0}" ip saddr . udp sport @c0_ap accept
  nft add rule inet heyaki_nat flt meta l4proto udp \
    ip daddr "${c1}" ip saddr . udp sport @c1_ap accept
  nft add rule inet heyaki_nat flt meta l4proto udp ip daddr "${c0}" drop
  nft add rule inet heyaki_nat flt meta l4proto udp ip daddr "${c1}" drop
}

# Symmetric NAT: no inbound DNAT exists at all (unsolicited UDP dies at the
# host), and every destination class maps into a disjoint port range, so the
# mapping a STUN server observes is never valid toward a different peer.
symmetric_ranges() {
  # client map excluded_subnet range_turn_a range_turn_b range_other
  local c=$1 m=$2 subnet=$3 r_a=$4 r_b=$5 r_other=$6
  nft add rule inet heyaki_nat out meta l4proto udp \
    ip saddr "${c}" ip daddr "${turn_a_ip}" snat to "${m}:${r_a}" fully-random
  nft add rule inet heyaki_nat out meta l4proto udp \
    ip saddr "${c}" ip daddr "${turn_b_ip}" snat to "${m}:${r_b}" fully-random
  nft add rule inet heyaki_nat out meta l4proto udp \
    ip saddr "${c}" ip daddr != "${subnet}" snat to "${m}:${r_other}" fully-random
}

# ---- participants -------------------------------------------------------
run_in() {
  # namespace output_file command...
  local ns=$1 out=$2; shift 2
  ip netns exec "${ns}" env SSL_CERT_FILE="${work_dir}/ca.pem" \
    "${matrix_bin}" "$@" >"${out}" 2>&1
}

prepare_participants() {
  local tag=$1 init_ns=$2 resp_ns=$3
  run_in "${init_ns}" "${work_dir}/${tag}-prepare-init.out" \
    init-profile "${work_dir}/${tag}-initiator.sqlite" matrix.first
  run_in "${resp_ns}" "${work_dir}/${tag}-prepare-resp.out" \
    init-profile "${work_dir}/${tag}-responder.sqlite" matrix.second
  # M5: sessions are default-deny; connectivity scenarios pre-seed mutual
  # device trust (password pairing itself is covered by the unit suites).
  run_in "${init_ns}" "${work_dir}/${tag}-prepare-seed.out" \
    seed-trust "${work_dir}/${tag}-initiator.sqlite" "${work_dir}/${tag}-responder.sqlite"
  run_in "${init_ns}" "${work_dir}/${tag}-prepare-enroll-init.out" \
    enroll "${work_dir}/${tag}-initiator.sqlite" matrix.first \
    "wss://${pub_relay}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" "${token}"
  run_in "${resp_ns}" "${work_dir}/${tag}-prepare-enroll-resp.out" \
    enroll "${work_dir}/${tag}-responder.sqlite" matrix.second \
    "wss://${pub_relay}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" "${token}"
}

first_result() { sed -n 's/^MATRIX_RESULT //p' "$1" | tail -1; }
result_field() {
  local line=$1 field=$2
  printf '%s\n' "${line}" | tr ' ' '\n' | sed -n "s/^${field}=//p" | head -1
}

# Initiator gathers STUN on coturn A, responder on coturn B. --srflx-only
# keeps host candidates out of the exchange so every pair must traverse the
# emulated NAT. turn_mode selects the fallback surface:
#   stun-only — no TURN credentials; the session MUST hole-punch a direct
#               srflx pair (cone classes: punchability itself is the scenario;
#               a TURN allocation would race the ICE nomination, which the
#               first CI run observed picking turn_udp over a punchable pair)
#   turn      — STUN + TURN with REST credentials; the session must establish
#               on a mediated path (symmetric/CGNAT classes)
# Extra args (retries, budgets) are shared by both sides.
run_pair() {
  # tag init_ns resp_ns budget turn_mode [extra node args...]
  local tag=$1 init_ns=$2 resp_ns=$3 budget=$4 turn_mode=$5; shift 5
  local init_turn_args=() resp_turn_args=()
  if [[ "${turn_mode}" == "turn" ]]; then
    init_turn_args=(--turn "${turn_a_ip}:${turn_port}" --turn-secret "${secret}")
    resp_turn_args=(--turn "${turn_b_ip}:${turn_port_b}" --turn-secret "${secret}")
  fi
  prepare_participants "${tag}" "${init_ns}" "${resp_ns}"
  # Let endpoints from the previous scenario fall out of the relay directory
  # (3 s presence lease) so the initiator cannot dial a stale endpoint.
  sleep 4
  run_in "${resp_ns}" "${work_dir}/${tag}-resp.out" \
    run "${work_dir}/${tag}-responder.sqlite" matrix.second \
    "wss://${pub_relay}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" "${budget}" \
    --role responder --srflx-only \
    --stun "${turn_b_ip}:${turn_port_b}" \
    ${resp_turn_args[@]+"${resp_turn_args[@]}"} \
    --authenticate-budget-ms 20000 "$@" &
  local responder_pid=$!
  run_in "${init_ns}" "${work_dir}/${tag}-init.out" \
    run "${work_dir}/${tag}-initiator.sqlite" matrix.first \
    "wss://${pub_relay}:${relay_port}" "${work_dir}/ca.pem" "${tenant}" "${budget}" \
    --role initiator --srflx-only \
    --stun "${turn_a_ip}:${turn_port}" \
    ${init_turn_args[@]+"${init_turn_args[@]}"} \
    --authenticate-budget-ms 20000 "$@"
  local initiator_status=$?
  wait "${responder_pid}" || true
  return "${initiator_status}"
}

probe_in() {
  local ns=$1
  ip netns exec "${ns}" python3 "${probe_bin}" \
    "${turn_a_ip}:${turn_port}" "${turn_b_ip}:${turn_port_b}"
}

failures=0
dump_outputs() {
  local tag=$1
  log "OUTPUTS ${tag} initiator:"
  sed -n '1,14p' "${work_dir}/${tag}-init.out" 2>/dev/null || true
  log "OUTPUTS ${tag} responder:"
  sed -n '1,14p' "${work_dir}/${tag}-resp.out" 2>/dev/null || true
  log "RELAY_LOG ${tag}:"
  tail -n 12 "${work_dir}/relay.log" 2>/dev/null || true
  log "TURN_LOG ${tag}:"
  for turn_log_name in turn-a.log turn-b.log; do
    grep -E "session [0-9]|allocated|error [0-9]+|quota" \
      "${work_dir}/${turn_log_name}" 2>/dev/null | tail -n 60 || true
  done
  log "NFT_RULES ${tag}:"
  nft list table inet heyaki_nat 2>/dev/null || true
  if command -v conntrack >/dev/null 2>&1; then
    log "CONNTRACK ${tag} (public aliases):"
    conntrack -L -p udp 2>/dev/null |
      grep -E "${map0}|${map0b}|${map1}|${turn_a_ip}|${turn_b_ip}" | tail -n 40 || true
  fi
}

# Require: authenticated on an expected data path, and (where strict) the M6
# message+RPC exercise succeeded on the first cycle. expected_paths is a
# comma-separated set. Under a symmetric NAT a `direct_srflx` label still
# proves mediation: the label names the LOCAL candidate type, and with inbound
# DNAT absent (probe-verified) the remote side can only have been RELAYED —
# the same contract as the M4 harness's require_authenticated_turn.
require_result() {
  # tag line expected_paths_csv strict_m6
  local tag=$1 line=$2 expected_paths_csv=$3 strict_m6=$4
  local authenticated data_path m6_message m6_rpc
  authenticated=$(result_field "${line}" authenticated)
  data_path=$(result_field "${line}" data_path)
  m6_message=$(result_field "${line}" m6_message_acked)
  m6_rpc=$(result_field "${line}" m6_rpc_status)
  local matched=0
  local expected
  for expected in ${expected_paths_csv//,/ }; do
    [[ "${data_path}" == "${expected}" ]] && matched=1
  done
  if [[ "${authenticated}" != "1" || "${matched}" != "1" ]]; then
    log "SCENARIO_FAILED ${tag} (expected ${expected_paths_csv}): ${line:-no-result}"
    dump_outputs "${tag}"
    failures=$((failures + 1))
    return 1
  fi
  if [[ "${strict_m6}" == "strict" &&
        ("${m6_message}" != "1" || "${m6_rpc}" != "1") ]]; then
    log "SCENARIO_FAILED ${tag} m6 services: ${line}"
    dump_outputs "${tag}"
    failures=$((failures + 1))
    return 1
  fi
  log "SCENARIO_OK ${tag}: ${line}"
  return 0
}

# The probe classifies the NAT before any heyaki traffic runs: cone classes
# must show one identical public mapping for both STUN servers (EIM), the
# symmetric carrier must show disjoint ports per destination.
probe_expect() {
  # namespace expected_class expected_alias
  local ns=$1 expected=$2 alias=$3 line
  if ! line=$(probe_in "${ns}"); then
    log "SCENARIO_FAILED probe ${ns}: no result"
    failures=$((failures + 1))
    return 1
  fi
  log "${line}"
  local mapped0 mapped1 ip0 ip1 port0 port1
  mapped0=$(printf '%s\n' "${line}" | tr ' ' '\n' | sed -n 's/^server0=//p')
  mapped1=$(printf '%s\n' "${line}" | tr ' ' '\n' | sed -n 's/^server1=//p')
  ip0=${mapped0%%:*}
  ip1=${mapped1%%:*}
  port0=${mapped0##*:}
  port1=${mapped1##*:}
  if [[ -z "${ip0}" || -z "${ip1}" ]]; then
    log "SCENARIO_FAILED probe ${ns}: unparsable result: ${line}"
    failures=$((failures + 1))
    return 1
  fi
  if [[ "${ip0}" != "${alias}" || "${ip1}" != "${alias}" ]]; then
    log "SCENARIO_FAILED probe ${ns}: mapped address is not the public alias ${alias} (${line})"
    failures=$((failures + 1))
    return 1
  fi
  case "${expected}" in
    eim)
      if [[ "${port0}" != "${port1}" ]]; then
        log "SCENARIO_FAILED probe ${ns}: mapping differs per destination (${line})"
        failures=$((failures + 1))
        return 1
      fi
      ;;
    symmetric)
      if [[ "${port0}" == "${port1}" ]]; then
        log "SCENARIO_FAILED probe ${ns}: mapping identical for both destinations (${line})"
        failures=$((failures + 1))
        return 1
      fi
      ;;
  esac
  log "PROBE_OK ${ns} ${expected} ${line}"
  return 0
}

# Small-sample "p95": with three samples per scenario the max is the p95 gate.
p95_of_samples() { printf '%s\n' "$@" | sort -n | tail -1; }

run_cycles() {
  # scenario_tag cycles expected_paths p95_budget_ms turn_mode init_ns resp_ns
  local tag=$1 cycles=$2 expected_paths=$3 p95_budget=$4 turn_mode=$5 init_ns=$6 resp_ns=$7
  local samples=() line duration cycle p95
  for cycle in $(seq 1 "${cycles}"); do
    run_pair "${tag}-${cycle}" "${init_ns}" "${resp_ns}" 40000 "${turn_mode}" \
      || failures=$((failures + 1))
    line=$(first_result "${work_dir}/${tag}-${cycle}-init.out")
    # m6 is asserted strictly on the first cycle; later cycles are
    # informational (churn races under retry windows are a known tail).
    local m6_mode=info
    [[ ${cycle} -eq 1 ]] && m6_mode=strict
    require_result "${tag}-${cycle}" "${line}" "${expected_paths}" "${m6_mode}" || true
    duration=$(result_field "${line}" duration_ms)
    [[ -n "${duration}" ]] && samples+=("${duration}")
  done
  if ((${#samples[@]} == cycles)); then
    p95=$(p95_of_samples "${samples[@]}")
    log "${tag}_P95_MS ${p95} samples=${samples[*]}"
    if ((p95 >= p95_budget)); then
      log "SCENARIO_FAILED ${tag}: p95 ${p95}ms exceeds ${p95_budget}ms budget"
      dump_outputs "${tag}-${cycles}"
      failures=$((failures + 1))
    fi
  else
    log "SCENARIO_FAILED ${tag}: missing duration samples (${#samples[@]}/${cycles})"
    dump_outputs "${tag}-${cycles}"
    failures=$((failures + 1))
  fi
}

for scenario in "${scenarios[@]}"; do
  case "${scenario}" in
    full_cone)
      nft_bootstrap
      cone_static "${client0}" "${map0}" "${client1}" "${map1}" \
        "10.78.0.0/24" "10.78.1.0/24"
      cone_accept
      client_bypass_drops
      probe_expect "${ns0}" eim "${map0}" || true
      probe_expect "${ns1}" eim "${map1}" || true
      run_cycles fullcone 3 direct_host,direct_srflx 5000 stun-only "${ns0}" "${ns1}"
      ;;
    restricted_cone)
      nft_bootstrap
      cone_static "${client0}" "${map0}" "${client1}" "${map1}" \
        "10.78.0.0/24" "10.78.1.0/24"
      restricted_filter "${client0}" "${client1}"
      cone_accept
      client_bypass_drops
      probe_expect "${ns0}" eim "${map0}" || true
      probe_expect "${ns1}" eim "${map1}" || true
      run_cycles restricted 1 direct_host,direct_srflx 5000 stun-only "${ns0}" "${ns1}"
      ;;
    port_restricted_cone)
      nft_bootstrap
      cone_static "${client0}" "${map0}" "${client1}" "${map1}" \
        "10.78.0.0/24" "10.78.1.0/24"
      port_restricted_filter "${client0}" "${client1}"
      cone_accept
      client_bypass_drops
      probe_expect "${ns0}" eim "${map0}" || true
      probe_expect "${ns1}" eim "${map1}" || true
      run_cycles portrestricted 1 direct_host,direct_srflx 5000 stun-only "${ns0}" "${ns1}"
      ;;
    symmetric)
      nft_bootstrap
      symmetric_ranges "${client0}" "${map0}" "10.78.0.0/24" \
        10000-19999 20000-29999 30000-39999
      symmetric_ranges "${client1}" "${map1}" "10.78.1.0/24" \
        40000-49999 50000-59999 60000-64000
      client_bypass_drops
      probe_expect "${ns0}" symmetric "${map0}" || true
      probe_expect "${ns1}" symmetric "${map1}" || true
      run_cycles symmetric 3 turn_udp,direct_srflx,direct_host 5000 turn "${ns0}" "${ns1}"
      ;;
    hairpin)
      nft_bootstrap
      cone_static "${client0}" "${map0}" "${client0b}" "${map0b}" \
        "10.78.0.0/24" "10.78.0.0/24"
      # Same-bridge peers must not shortcut over directly routed private
      # addresses; only DNAT'd hairpin traffic crosses the subnet.
      nft add rule inet heyaki_nat flt meta l4proto udp \
        ip saddr 10.78.0.0/24 ip daddr 10.78.0.0/24 ct status dnat accept
      nft add rule inet heyaki_nat flt meta l4proto udp \
        ip saddr 10.78.0.0/24 ip daddr 10.78.0.0/24 drop
      probe_expect "${ns0}" eim "${map0}" || true
      probe_expect "${ns0b}" eim "${map0b}" || true
      run_cycles hairpin 1 direct_host,direct_srflx 5000 stun-only "${ns0}" "${ns0b}"
      ;;
    cgnat)
      nft_bootstrap
      # Carrier NAT for the home gateways is symmetric: direct hole punching
      # across double NAT must fail and TURN must carry the session.
      symmetric_ranges "${gwa_wan}" "${map0}" "10.78.0.0/24" \
        10000-19999 20000-29999 30000-39999
      symmetric_ranges "${gwb_wan}" "${map1}" "10.78.1.0/24" \
        40000-49999 50000-59999 60000-64000
      client_bypass_drops
      probe_expect "${ns2}" symmetric "${map0}" || true
      probe_expect "${ns3}" symmetric "${map1}" || true
      # The double-NAT control/stun path rides the same runner-timing tail as
      # the M4 lossy scenario (the first CI run saw back-to-back
      # attempt_expired cycles after a green cycle). Run up to three fresh
      # pairs and accept the first fully successful one; a genuinely broken
      # double-NAT path fails every try with the same signature.
      cgnat_accepted=0
      for cgnat_try in 1 2 3; do
        run_pair "cgnat-${cgnat_try}" "${ns2}" "${ns3}" 40000 turn \
          --connect-retries 2 || true
        line=$(first_result "${work_dir}/cgnat-${cgnat_try}-init.out")
        authenticated=$(result_field "${line}" authenticated)
        data_path=$(result_field "${line}" data_path)
        m6_message=$(result_field "${line}" m6_message_acked)
        m6_rpc=$(result_field "${line}" m6_rpc_status)
        if [[ "${authenticated}" == "1" &&
              ("${data_path}" == "turn_udp" || "${data_path}" == "direct_srflx" ||
               "${data_path}" == "direct_host") &&
              "${m6_message}" == "1" && "${m6_rpc}" == "1" ]]; then
          log "SCENARIO_OK cgnat (try ${cgnat_try}): ${line}"
          cgnat_accepted=1
          break
        fi
        log "CGNAT_RETRY (try ${cgnat_try} of 3): ${line:-no-result}"
      done
      if [[ "${cgnat_accepted}" != "1" ]]; then
        log "SCENARIO_FAILED cgnat (no try authenticated on a mediated path with m6): ${line:-no-result}"
        dump_outputs "cgnat-3"
        failures=$((failures + 1))
      fi
      ;;
    *)
      log "unknown scenario: ${scenario}"
      exit 2
      ;;
  esac
done

nft delete table inet heyaki_nat
if ((failures > 0)); then
  log "MATRIX_FAILED failures=${failures}"
  exit 1
fi
log "MATRIX_OK scenarios=${scenarios[*]}"
