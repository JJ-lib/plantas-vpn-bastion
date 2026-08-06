# Repository boundary

This repository is a generic source monorepo, not a snapshot of a running bastion or a customer deployment.

## Versioned

- application source and tests;
- Dockerfiles and generic Compose structure;
- generic templates for generated site overlays and proxy declarations;
- customized Guacamole source and upstream licensing files;
- documentation, validation rules, GitHub automation, and neutral SVG assets.

## External by policy

The following remain in the protected deployment or secret-management system:

- `.env` values and signing keys;
- Fortinet, OpenVPN, Libreswan, and strongSwan credentials, profiles, PSKs, and private certificates;
- SQLite databases, Fernet keys, Docker volumes, cookies, tokens, and generated runtime files;
- generated Compose overlays, proxy declarations, and site directories;
- equipment inventories, internal addresses, public endpoints, customer names, and customer-specific screenshots;
- host-specific paths, emergency overrides, and unreviewed generated configuration.

The public repository must never contain customer deployment names, site directories, equipment inventories, internal addresses, public endpoints, generated overlays, credentials, or raw diagnostics.

## Promotion boundary

A repository commit is not a production deployment. Promotion must verify the exact commit, image digests, configuration hashes, tunnel/SA/interface gates, and a scoped canary. Any mutation after an approval invalidates that approval.
