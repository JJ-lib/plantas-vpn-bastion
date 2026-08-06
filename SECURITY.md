# Security policy

Bastión VPN is remote-access infrastructure. A vulnerability may provide a path into customer or plant networks, so do not disclose exploit details in a public issue.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/juanuto/plantas-vpn-bastion/security/advisories/new) when available. If the repository cannot receive an advisory, contact the maintainers through a private GitHub channel and include only the minimum reproduction needed to triage the issue.

Do not attach VPN profiles, PSKs, passwords, private keys, certificates, cookies, tokens, customer names, gateways, internal addresses, databases, Docker volume archives, or raw logs.

## Scope and response

The security boundary includes the control plane, VPN/proxy images, Caddy and Guacamole ingress, plant Compose overlays, generated configuration, and deployment tooling. Maintainers will reproduce with synthetic fixtures where possible, assess impact, prepare a minimal fix, and publish remediation guidance when safe.

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model and [SUPPORT.md](SUPPORT.md) for non-security questions.
