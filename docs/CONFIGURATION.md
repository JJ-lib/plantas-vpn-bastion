# Configuration

Bastión VPN separates declared intent, secrets, and runtime state. This keeps reviews useful and prevents a Git checkout from becoming a credential archive.

## Configuration layers

| Layer | Examples | Git policy |
| --- | --- | --- |
| Intent | Compose, HAProxy, Caddy, templates, source, tests | Version and review |
| Secrets | `.env`, VPN profiles, PSKs, passwords, private certificates | External only |
| Runtime | SQLite, Docker volumes, generated files, logs, diagnostics | External and backed up separately |

## Environment contract

The tracked `.env.example` documents names only:

- `BASTION_PROJECT_ROOT` — host path mounted into the control plane; the example is `/opt/bastion-vpn`.
- `BASTION_PUBLIC_ORIGIN` — deployment origin used for generated URLs.
- `BASTION_ACCESS_CIDRS` — deployment return routes supplied outside Git.
- `VALIDATION_DENY_CIDRS` — deployment validation policy supplied outside Git.
- `PANEL_IMAGE`, `RECONCILER_IMAGE`, `GUACD_IMAGE`, and `GUACAMOLE_IMAGE` — immutable image references supplied by promotion.
- `GUAC_JSON_KEY` — shared JSON authentication/signing secret for Guacamole.
- `VPN_ENDPOINT_MONITOR_TOKEN_FILE` — external bearer-token file shared read-only by the panel and monitor.
- `VPN_ENDPOINT_MONITOR_COLLECTION_ENABLED` — fail-closed switch for target collection/result ingestion; default `false`.
- `VPN_ENDPOINT_ADMIN_DIAGNOSTICS_ENABLED` — fail-closed switch for endpoint details on administrator VPN pages; default `false`.
- `VPN_ENDPOINT_PUBLIC_ALERTS_ENABLED` — ordinary-user card alerts; default `false` and independent of the two monitor gates.
- `VPN_ENDPOINT_MONITOR_TARGET_IDS` — comma-separated numeric VPN IDs for a canary allowlist. An explicit empty value selects no targets; an unset selector is the distinct all-target production mode.

Use a secret manager or a protected root-owned `.env` file with mode `0600`. Never print values during diagnostics.

### Pinned IKE probe

The monitor image installs the Debian Bookworm package `ike-scan=1.9.5-2`. The packaged upstream binary reports `ike-scan 1.9.6`; both values are intentional and are verified during image validation. The monitor invokes only the credential-free, allowlisted adapter and never supplies PSKs, certificates, or VPN profiles.

## Root Compose services

- `panel` — Flask application and administrative control plane;
- `vpn-reconciler` — applies declared VPN lifecycle state to Docker;
- `guacd` — Guacamole protocol daemon;
- `guacamole` — browser remote-access endpoint with JSON authentication;
- `caddy` — ingress and static portal service.

The root Compose file also defines the shared `bastion_net` network and persistent Caddy/panel volumes.

## Endpoint-monitor promotion gates

Keep collection, administrator diagnostics, and ordinary-user alerts disabled while promoting the monitor. Enable collection only after the worker image and token contract are verified. Start a canary with `VPN_ENDPOINT_MONITOR_TARGET_IDS` containing only approved existing VPN IDs; the worker filters the panel's real target snapshot and never creates a synthetic VPN row. An empty selector is fail-closed and probes nothing. Do not use an all-target run until promotion is explicitly approved.

Ordinary users receive only the generic alert text when the public-alert flag is enabled and the health policy confirms two failures while the tunnel is offline. They never receive gateway hostnames, addresses, ports, latency, probe codes, commands, or raw diagnostics. Administrator endpoint details remain unavailable unless the separate diagnostics flag is enabled.

## Generated site overlays

The public tree does not contain generated `sites/` or site-specific `configs/` directories. The panel or the deployment operator generates those files from a reviewed template and protected inputs under the deployment boundary. They must never be copied back into this repository.

## HAProxy declarations

Add only the target ports users need. A TCP publication should have a named frontend/backend and bounded health checks. HTTP publication should account for base paths, WebSockets, redirects, and TLS behavior.

```haproxy
frontend scada_http
    bind *:8080
    mode http
    default_backend scada_target

backend scada_target
    mode http
    server scada 192.0.2.20:80 check
```

## Adding configuration safely

1. Start from `templates/` or a synthetic example.
2. Keep gateways, usernames, passwords, certificate fingerprints, and private target lists outside Git when deployment-specific.
3. Run Compose validation and focused tests.
4. Review staged files and scan for credential-like content.
5. Promote manually with [INSTALL.md](INSTALL.md).

## Compatibility rule

Do not rename site slugs, container names, image tags, or proxy ports casually. They may be referenced by Caddy, Guacamole, bookmarks, or rollback automation. A rename is a migration, not cleanup.
