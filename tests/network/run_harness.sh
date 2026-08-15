#!/usr/bin/env bash

set -euo pipefail

skip() {
  if [[ "${HEYAKI_REQUIRE_NETWORK_HARNESS:-0}" == "1" ]]; then
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
  fi
  printf 'SKIP: %s\n' "$1"
  exit 77
}

[[ $# -eq 1 ]] || {
  printf 'usage: %s <m3a-test-binary>\n' "$0" >&2
  exit 2
}

heyaki_m3a_test=$1
[[ -x "${heyaki_m3a_test}" ]] || skip "M3A test binary is unavailable"
[[ "$(uname -s)" == "Linux" ]] || skip "network namespace harness is Linux-only"

for heyaki_tool in unshare ip nft tc sysctl timeout; do
  command -v "${heyaki_tool}" >/dev/null 2>&1 || \
    skip "${heyaki_tool} is required for the network namespace harness"
done

if [[ "${HEYAKI_NETWORK_HARNESS_CHILD:-0}" != "1" ]]; then
  if [[ ${EUID} -eq 0 ]]; then
    unshare --net true >/dev/null 2>&1 || \
      skip "network namespaces are unavailable to this test process"
    exec unshare --net \
      env HEYAKI_NETWORK_HARNESS_CHILD=1 \
        HEYAKI_REQUIRE_NETWORK_HARNESS="${HEYAKI_REQUIRE_NETWORK_HARNESS:-0}" \
        bash "$0" "${heyaki_m3a_test}"
  fi
  if unshare --user --map-root-user --net true >/dev/null 2>&1; then
    exec unshare --user --map-root-user --net \
      env HEYAKI_NETWORK_HARNESS_CHILD=1 \
        HEYAKI_REQUIRE_NETWORK_HARNESS="${HEYAKI_REQUIRE_NETWORK_HARNESS:-0}" \
        bash "$0" "${heyaki_m3a_test}"
  fi
  if command -v sudo >/dev/null 2>&1 &&
     sudo -n unshare --net true >/dev/null 2>&1; then
    exec sudo -n unshare --net \
      env HEYAKI_NETWORK_HARNESS_CHILD=1 \
        HEYAKI_REQUIRE_NETWORK_HARNESS="${HEYAKI_REQUIRE_NETWORK_HARNESS:-0}" \
        bash "$0" "${heyaki_m3a_test}"
  fi
  skip "user/network namespaces are unavailable to this test process"
fi

ip link set lo up 2>/dev/null || \
  skip "the isolated namespace does not grant CAP_NET_ADMIN"
nft add table inet heyaki_test 2>/dev/null || \
  skip "nftables is blocked in the isolated namespace"
nft add chain inet heyaki_test output \
  '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || \
  skip "nftables hook creation is blocked in the isolated namespace"
tc qdisc add dev lo root netem delay 1ms loss 0% 2>/dev/null || \
  skip "netem is blocked in the isolated namespace"
tc qdisc del dev lo root

delete_links() {
  ip link del hya >/dev/null 2>&1 || true
  ip link del hyc >/dev/null 2>&1 || true
}

create_pair() {
  local first=$1
  local second=$2
  ip link add "${first}" type veth peer name "${second}"
}

run_m3a() {
  local label=$1
  local filter=$2
  shift 2
  printf 'M3A network topology: %s\n' "${label}"
  timeout 45s env "$@" "${heyaki_m3a_test}" --gtest_filter="${filter}"
}

delete_links
create_pair hya hyb
sysctl -qw net.ipv6.conf.hya.disable_ipv6=1
sysctl -qw net.ipv6.conf.hyb.disable_ipv6=1
ip addr add 192.0.2.1/24 dev hya
ip addr add 192.0.2.2/24 dev hyb
ip link set hya up
ip link set hyb up
run_m3a ipv4-only \
  'M3aNodeTest.TwoLanNodesDiscoverEachOtherWithoutRelay:M3aNodeTest.AuthenticatesLanTlsAndForwardsBoundedControlMessages:M3aNodeTest.ThreeEndpointsIncludeTwoFromTheSameDevice:M3aNodeTest.RepeatedConnectCloseRemainsBounded:M3aNodeTest.RejectsForgedMulticastFloodWithinBounds'

delete_links
create_pair hya hyb
ip link set hya up
ip link set hyb up
ip -6 addr flush dev hya scope link
ip -6 addr flush dev hyb scope link
ip -6 addr add fe80::1/64 dev hya nodad
ip -6 addr add fe80::2/64 dev hyb nodad
run_m3a ipv6-link-local \
  'M3aNodeTest.TwoLanNodesDiscoverEachOtherWithoutRelay:M3aNodeTest.AuthenticatesLanTlsAndForwardsBoundedControlMessages:M3aNodeTest.ThreeEndpointsIncludeTwoFromTheSameDevice'

delete_links
create_pair hya hyb
create_pair hyc hyd
ip addr add 192.0.2.1/24 dev hya
ip addr add 192.0.2.2/24 dev hyb
ip addr add 198.51.100.1/24 dev hyc
ip addr add 198.51.100.2/24 dev hyd
ip link set hya up
ip link set hyb up
ip link set hyc up
ip link set hyd up
run_m3a dual-stack-multi-interface \
  'M3aNodeTest.NetworkTopologyMatchesExpectedInterfaces:M3aNodeTest.RefreshesSocketsAfterInterfaceSwitch:M3aNodeTest.TwoLanNodesDiscoverEachOtherWithoutRelay' \
  HEYAKI_EXPECT_IPV4_INTERFACES=4 \
  HEYAKI_EXPECT_IPV6_INTERFACES=4 \
  HEYAKI_SWITCH_INTERFACE=hya

nft add rule inet heyaki_test output udp dport 49189 drop
run_m3a multicast-blocked \
  'M3aNodeTest.BlockedMulticastFailsPeerLookupAndShutdowns' \
  HEYAKI_EXPECT_MULTICAST_BLOCKED=1
nft flush chain inet heyaki_test output

delete_links
nft delete table inet heyaki_test
printf 'M3A network harness passed IPv4, IPv6, multi-interface, switch, and blocked multicast scenarios\n'
