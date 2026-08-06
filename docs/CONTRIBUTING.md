# Contributing

Bastión VPN touches remote-access and OT-adjacent infrastructure, so a small, reviewable change is preferable to a broad refactor.

## Before you start

Read [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and [repository-boundary.md](repository-boundary.md). Decide whether the change affects the control plane, a plant namespace, a proxy contract, or documentation only.

## Workflow

1. Create a focused branch from `main`.
2. Add or update a regression test for behavior changes.
3. Keep deployment-specific values synthetic or external.
4. Update the relevant canonical documentation.
5. Run the checks below.
6. Open a pull request explaining compatibility, rollback, and operational impact.

```bash
python -m compileall -q panel-app tests
python tests/run_full_suite.py
docker compose config --quiet
python guacamole-server/test_clipboard_file_transfer_contract.py
```

GitHub Actions also runs Markdown, YAML, Compose, ShellCheck, link, and spelling workflows.

For private repositories on plans without branch-protection support, maintainers must enforce this Pull Request and green-check policy manually until the repository is moved to a supported plan. Production promotion remains a separate, manual approval step.

## Pull requests

Include a problem statement, design, exact boundaries changed, tests, migration/rollback notes, security impact, and operator documentation. Never include credentials, live profiles, raw logs, private keys, encrypted payloads, or unredacted topology.

## Review principles

Preserve existing names and ports unless a migration is included. Prefer explicit allowlists over broad routing. Keep privileged operations narrow and observable. Treat CI failures as evidence, not as reasons to weaken checks.
