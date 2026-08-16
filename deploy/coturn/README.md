# Heyaki coturn deployment baseline

coturn is an external runtime component. It is not linked into `heyaki-relay` and is not
started by the relay process.

## Pinned artifact

- Container image: `coturn/coturn:4.10.0-debian`
- Immutable digest: `sha256:f4c2af06c3c535c4f49d64e14d484104e7e4fcc98c4cb83d6e1544f64d1e6158`
- Fallback package baseline: Ubuntu 24.04 `coturn=4.6.1-1build4` (apt, universe)

The container digest is authoritative for deployed images. The package version is the
fallback baseline for hosts that install coturn with the OS package manager; release
provenance must record the exact package digest from the target repository.

## Credential contract

Heyaki uses coturn TURN REST API credentials:

- `username = <expiry_unix_seconds>:<tenant>:<DeviceId>`
- `password = base64(HMAC-SHA1(static-auth-secret, username))`
- Credentials are short-lived (default 600 seconds), bound to device, tenant, and expiry.
- The relay keeps at most four secret generations, so rotated credentials remain valid
  until their expiry while new issues use the latest generation.
- `static-auth-secret` is never committed to the repository or written to relay logs.
  It is supplied through the deployment environment as `HEYAKI_TURN_SECRET`.

## Resource policy

- Client listeners: UDP/TCP 3478 and TLS 5349.
- Allocation ports: 49160-49200.
- Total allocation quota: 100; per-user quota: 12.
- Per-session bandwidth: 2 Mbit/s each direction; server capacity: 16 Mbit/s each direction.
- Maximum allocation lifetime: 3600 seconds.
- Private/link-local/loopback peer ranges are denied to prevent relay-to-management-network
  pivoting. coturn denies loopback peers by default and the config keeps the explicit
  `denied-peer-ip=127.0.0.0-127.255.255.255` range; the legacy `no-loopback-peers`
  option is not used because the pinned 4.10.0 image does not support it.
- `external-ip` advertises the configured public address for the configured local address.
  Local test topologies set both to the host bridge address.

## Local test topology

`run_topology.sh` creates two isolated network namespaces connected to two host bridges,
blocks inter-client forwarding, starts coturn and `heyaki-relay` on the host, verifies STUN
reachability from both namespaces and WSS reachability to the relay, then tears everything
down. coturn remains a separate process/container and is never embedded in `heyaki-relay`.

`run_allocation_probe.sh` validates the TURN REST API credential contract against a real
coturn process without root privileges: it generates a temporary certificate, starts the
same checked-in resource-policy template on ports above 1024, obtains a TURN allocation
for `username = <expiry>:<tenant>:<DeviceId>`, verifies relayed data admission, and checks
that coturn logs do not contain `static-auth-secret`. Set `HEYAKI_COTURN_ROOT` to an
extracted `coturn/coturn:4.10.0-debian` rootfs to probe the pinned image binary directly.

## Run

```sh
cp heyaki-turn.env.example .env
# set HEYAKI_TURN_SECRET to at least 16 printable ASCII characters
docker compose --env-file .env up -d
```

The compose file uses host networking so coturn can allocate the configured UDP/TCP
relay port range on the public interface. Do not run coturn inside the relay container.
