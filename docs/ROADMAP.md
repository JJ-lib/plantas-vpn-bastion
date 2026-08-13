# Roadmap

The roadmap is capability-based. Dates are omitted until the project has a public release cadence and support policy.

| Release | Focus | Definition of done |
| --- | --- | --- |
| `0.2` | Portable deployments | External host paths, documented image supply chain, synthetic demo profile, and backup/restore boundary. |
| `0.3` | Governance | User lifecycle, RBAC by plant/equipment, audit events, session expiry, and access reviews. |
| `0.4` | Engine adapters | Common health contract for OpenVPN, WireGuard, Fortinet SSL, Libreswan, and strongSwan. |
| `0.5` | Observability | Metrics, structured redacted events, dashboards, alerts, and canary history. |
| `0.6` | API and plugins | Versioned REST API, plugin contract, import/export validation, and compatibility tests. |
| `1.0` | Enterprise baseline | HA, supported upgrades, recovery objectives, security advisories, and stable configuration contract. |

## Completed capability: public VPN endpoint monitoring

- [x] Immediate first cycle and monotonic 60-second start-to-start scheduling with bounded failure backoff.
- [x] Two ICMP attempts plus protocol-specific TCP, OpenVPN UDP, IKEv1/IKEv2, NAT-T, and PPTP probes without credentials.
- [x] Authenticated internal API, normalized results, DNS rebinding/SSRF controls, and `icmp_ok OR protocol_ok` accessibility semantics.
- [x] SQLite WAL persistence, three-failure transition threshold, one-success recovery, transition events, and five-hour history.
- [x] Admin diagnostics and public alerts with tunnel/endpoint separation and no endpoint details exposed to ordinary users.
- [x] Non-root read-only monitor with only `CAP_NET_RAW`, no Docker/SQLite/VPN credentials, dedicated networks, and persistent fail-closed nftables policy.
- [x] Canary production acceptance with immutable images, scoped promotion/rollback, real probes, host reboot, firewall-before-Docker ordering, and post-boot recovery.

## Priorities

1. Preserve isolation and fail-closed promotion.
2. Make clean installation reproducible without weakening secret handling.
3. Add governance before broad automation.
4. Support more engines behind the same validated lifecycle contract.
