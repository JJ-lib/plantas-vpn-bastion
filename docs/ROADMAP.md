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

## Priorities

1. Preserve isolation and fail-closed promotion.
2. Make clean installation reproducible without weakening secret handling.
3. Add governance before broad automation.
4. Support more engines behind the same validated lifecycle contract.
