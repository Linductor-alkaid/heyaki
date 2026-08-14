#!/usr/bin/env bash

set -euo pipefail

skip() {
  printf 'SKIP: %s\n' "$1"
  exit 77
}

[[ "$(uname -s)" == "Linux" ]] || skip "network namespace harness is Linux-only"

for heyaki_tool in unshare ip nft tc; do
  command -v "${heyaki_tool}" >/dev/null 2>&1 || \
    skip "${heyaki_tool} is required for the network namespace harness"
done

if [[ "${HEYAKI_NETWORK_HARNESS_CHILD:-0}" != "1" ]]; then
  if ! unshare --user --map-root-user --net true >/dev/null 2>&1; then
    skip "user/network namespaces are unavailable to this test process"
  fi
  exec unshare --user --map-root-user --net \
    env HEYAKI_NETWORK_HARNESS_CHILD=1 bash "$0"
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
nft delete table inet heyaki_test
printf 'network harness verified an isolated namespace with nftables and netem\n'
