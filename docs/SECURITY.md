# Security model

Bastión VPN is for controlled, self-hosted deployments. It reduces workstation routing complexity; it does not remove the need for network controls, account governance, patching, or incident response.

## Trust boundaries

1. **Operator to ingress:** authenticated traffic enters through the approved Caddy/Guacamole path.
2. **Ingress to control plane:** browser requests reach panel or Guacamole on the shared bastion network.
3. **Control plane to Docker:** panel/reconciler Docker socket access is a high-privilege boundary.
4. **Bastion to plant namespace:** only the selected proxy endpoint crosses into a plant data plane.
5. **VPN to target:** provider authentication and target authorization remain customer responsibilities.

## Isolation controls

- One plant VPN per container or isolated Compose namespace.
- Explicit HAProxy frontends instead of broad subnet publication.
- Separate per-plant configuration and lifecycle records.
- No direct workstation route installation.
- Health gates before activation and scoped canaries after promotion.

## Secret handling

Never commit or print `.env` values, signing keys, passwords, PSKs, tokens, cookies, OpenVPN/Fortinet profiles, private certificates, SQLite databases, Fernet keys, backups, raw diagnostics, or unredacted customer topology. A missing protected file must fail closed rather than become an empty or inferred credential.

## Privileged interfaces

The root Compose file mounts the Docker socket into panel and reconciler. Operators should restrict host access, audit image provenance and digests, avoid arbitrary web command execution, and preserve an independent break-glass procedure.

## Promotion policy

A verified bundle consists of exact source/image/config hashes plus recorded tunnel, SA, interface, route, and canary results. Any mutation after authorization invalidates it. Do not restart or recreate unrelated VPN containers during a focused change.

## Reporting

Use the [private security reporting path](https://github.com/juanuto/plantas-vpn-bastion/security/advisories/new). The root [SECURITY.md](../SECURITY.md) contains reporting and redaction rules.
