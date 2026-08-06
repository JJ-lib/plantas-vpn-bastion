# Configuration boundary

This directory is intentionally free of site-specific configuration. It contains policy and templates only; generated per-site files stay on the deployment host and are never committed.

## Never commit

Keep the following outside Git:

- VPN profiles, gateways, usernames, passwords, PSKs, certificates, and private keys;
- generated Compose overlays and proxy configuration;
- equipment inventories, internal addresses, public endpoints, and customer metadata;
- databases, exports, logs, diagnostics, backups, cookies, and runtime state.

A missing runtime file must stop a deployment rather than trigger a guessed or empty credential. Use the generic files under `templates/` with values supplied by the deployment's secret/configuration process.
