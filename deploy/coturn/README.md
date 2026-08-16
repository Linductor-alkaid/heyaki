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

## Run

```sh
cp heyaki-turn.env.example .env
# set HEYAKI_TURN_SECRET to at least 16 printable ASCII characters
docker compose --env-file .env up -d
```

The compose file uses host networking so coturn can allocate the configured UDP/TCP
relay port range on the public interface. Do not run coturn inside the relay container.
