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

Use a secret manager or a protected root-owned `.env` file with mode `0600`. Never print values during diagnostics.

## Root Compose services

- `panel` — Flask application and administrative control plane;
- `vpn-reconciler` — applies declared VPN lifecycle state to Docker;
- `guacd` — Guacamole protocol daemon;
- `guacamole` — browser remote-access endpoint with JSON authentication;
- `caddy` — ingress and static portal service.

The root Compose file also defines the shared `bastion_net` network and persistent Caddy/panel volumes.

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
