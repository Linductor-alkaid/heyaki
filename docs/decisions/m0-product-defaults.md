# M0 Product Decision Defaults

Status: provisional until the named freeze milestone. These defaults prevent engineering work from
stalling; they are not a substitute for product approval.

| ID | Provisional default | Owner | Freeze no later than |
| --- | --- | --- | --- |
| DEC-01 | MVP targets Linux x86_64; v1 also gates on Windows x64; constrained embedded targets are deferred. | Product + Architecture | M1 exit |
| DEC-02 | TURN/TCP/TLS is required for v1; authenticated HTTP proxy support is deferred. | Networking | M3 entry |
| DEC-03 | M0 uses configurable conservative limits; peer, RPC, subscriber, file-size, and throughput limits freeze after measurement. | Product + Performance | M5 entry, final values at M9 |
| DEC-04 | Default pairing grants a read/file template without Shell; password rotation does not automatically revoke existing grants. | Security + Product | M5 entry |
| DEC-05 | MVP is a single-tenant self-hosted relay; public multi-tenant service is deferred. | Product + Operations | M3 entry |
| DEC-06 | Shell is for interactive maintenance only; unattended work uses narrow RPC/job services. | Security + Product | M8 entry |
| DEC-07 | v1 does not promise lossless session migration across mobile network changes. | Networking + Product | M4 entry |
| DEC-08 | Default ProfileStore ownership is per-user; system services must name an explicit system profile. | Security + Platform | M2 entry |
| DEC-09 | A tenant sees only the endpoint capability summary required for connection selection. | Security + Product | M3 entry |

Any override must update the architecture, implementation plan, relevant protocol/security tests,
and this decision record in the same change.

