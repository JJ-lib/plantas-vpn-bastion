# VPN Public Endpoint Monitoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a read-only, protocol-aware monitor that probes active VPN public endpoints every five minutes and displays a site-card warning after two consecutive conclusive failures without modifying VPN runtime state.

**Architecture:** A least-privilege `vpn-endpoint-monitor` worker fetches sanitized targets and submits normalized results through authenticated internal Flask endpoints. The panel owns schema migration, revision checks, health transitions, diagnostic correlation, and UI rendering. The worker has outbound network access but no Docker socket, panel database, project tree, VPN profiles, or credential material.

**Tech Stack:** Python 3.12 stdlib, Flask, SQLite/WAL, Docker Compose, Caddy, `ike-scan`, unittest, temporary Linux Docker validation.

**TDD discipline:** Every production behavior starts with a focused failing test, the failure is observed for the intended missing behavior, and only then is the minimum implementation added. Focused tests return to green before the next behavior begins.

---

## File map

**Create**

- `panel-app/vpn_endpoint_health.py` — schema, target revisions, validation, state transitions, stale-state interpretation, safe UI DTOs.
- `panel-app/vpn_endpoint_monitor.py` — stateless worker, target API client, DNS/global-address policy, TCP/IKE/UDP probe normalization, bounded concurrent cycle.
- `images/vpn-endpoint-monitor/Dockerfile` — minimal non-root monitor image with pinned Python base and `ike-scan`.
- `tests/test_vpn_endpoint_health.py` — schema and deterministic state-machine tests.
- `tests/test_vpn_endpoint_monitor.py` — probe policy/command/normalization tests with fake resolvers and runners.
- `tests/test_vpn_endpoint_monitor_api.py` — internal authentication, redaction, active filtering, stale revision, and body validation tests.
- `tests/test_vpn_endpoint_monitor_ui.py` — authorized-user/admin rendering and tunnel-precedence tests.
- `tests/test_vpn_endpoint_monitor_integration.py` — Compose/Caddy/least-privilege contract tests.

**Modify**

- `panel-app/app.py` — initialize schema, expose authenticated internal endpoints, enrich targets, join health state into cards and admin VPN table.
- `panel-app/Dockerfile` — copy shared monitor modules only as needed by panel runtime.
- `docker-compose.yml` — panel secret mount, monitor service, immutable monitor image input, read-only/non-root hardening, internal network access.
- `caddy/Caddyfile` — fail closed for `/internal/*` before the panel catch-all.
- `.env.example` — document external monitor image and token-file contracts without secret values.
- `README.md`, `docs/ARCHITECTURE.md`, `docs/CONFIGURATION.md`, `docs/SECURITY.md` — behavior, evidence limits, configuration, and operational security.
- `tests/run_full_suite.py` — discovery should include the new test modules automatically; modify only if needed for deterministic ordering/isolation.

## Review gates added before implementation

The independent security review found blocking gaps. No probe or deployment task may be marked complete until these gates are covered by code, tests, and deployment verification:

1. Resolve and validate DNS once, then probe only the exact vetted numeric IP; reject IPv4-mapped private/reserved addresses and enforce host/network egress deny rules.
2. Treat IKE silence as inconclusive unless pinned `ike-scan` behavior, proposal coverage, source-port handling, and seconds-to-milliseconds timeout conversion are proven; serialize source-port-500 probes.
3. Add monotonic target generation plus panel-issued cycle/lease IDs; accept one result per VPN/generation/cycle, reject older cycles atomically, and make duplicate submissions idempotent.
4. Track panel acceptance and conclusive-observation timestamps separately; only fresh failures from distinct cycles can create a public alert. Suppress alerts on systemic monitor/DNS/tool failures.
5. Configure WAL and `busy_timeout` on every SQLite connection; use immediate/conditional atomic writes and file-backed multi-connection concurrency tests.
6. Keep collection, admin diagnostics, and ordinary-user alerts behind independent flags; default `VPN_ENDPOINT_PUBLIC_ALERTS_ENABLED=false`; canary selection must be explicit and must not create a production VPN row.
7. Specify secret UID/GID/mode/rotation, keep Flask auth mandatory, and black-box test Caddy denial for methods, encoded paths, doubled slashes, and route order.
8. Roll back only monitor artifacts; retain the additive health table and never restore the whole database for routine rollback.

## Task 1: Persist public-endpoint health with an atomic state machine

**Files:**
- Create: `panel-app/vpn_endpoint_health.py`
- Create: `tests/test_vpn_endpoint_health.py`
- Modify: `panel-app/app.py` only after the unit tests fail for the missing integration.

- [ ] **Step 1: Write failing schema tests**

Cover idempotent `ensure_endpoint_health_schema()`, one row per VPN, accepted states, and no mutation of `vpns.active`/onboarding columns.

- [ ] **Step 2: Run the focused test and verify RED**

Run in Linux:

```bash
PYTHONPATH=panel-app python -m unittest -v tests/test_vpn_endpoint_health.py
```

Expected: import/module failure because `vpn_endpoint_health.py` does not exist.

- [ ] **Step 3: Implement the minimal schema**

Create `vpn_endpoint_health` with the fields from the approved design and an FK-like logical `vpn_id` primary key. Keep migration idempotent and compatible with SQLite WAL.

- [ ] **Step 4: Write failing transition tests**

Cover:

- first failure → `suspect`, no alert;
- second consecutive conclusive failure → `down`;
- additional failure increments with a safe cap;
- first success → `healthy`, reset failure fields;
- inconclusive result preserves last conclusive state and does not increment;
- endpoint revision change resets state before applying a result;
- stale revision is rejected;
- last observation older than 15 minutes is interpreted as `stale` for admin display only.

- [ ] **Step 5: Run tests and verify RED for missing transition behavior**

- [ ] **Step 6: Implement `target_revision()`, `validate_result()`, `apply_probe_result()`, and `health_for_vpns()`**

Use parameterized SQL, bounded strings, strict enums, integer timestamp/latency ranges, and a transaction for read/compare/update.

- [ ] **Step 7: Run focused tests and verify GREEN**

- [ ] **Step 8: Integrate schema initialization in `app.py` and rerun focused tests**

## Task 2: Build safe target/result internal APIs

**Files:**
- Create: `tests/test_vpn_endpoint_monitor_api.py`
- Modify: `panel-app/app.py`
- Reuse: `panel-app/vpn_endpoint_health.py`

- [ ] **Step 1: Write failing authentication tests**

Cover missing/incorrect bearer token → indistinguishable 404, valid token → success, missing/unsafe token file → fail closed, constant-time comparison seam, and request body-size enforcement.

- [ ] **Step 2: Run focused API tests and verify RED**

- [ ] **Step 3: Implement token-file loading and internal auth decorator**

Read a deployment-provided file, require a bounded high-entropy token, compare with `hmac.compare_digest`, never log or return the token.

- [ ] **Step 4: Write failing target-contract tests**

Assert:

- active VPNs only;
- exact safe allowlist of fields;
- no fields containing password, PSK, certificate, profile, internal selector, or encrypted material;
- OpenVPN transport is derived inside the panel without returning profile content;
- target revision changes when probe-relevant configuration changes.

- [ ] **Step 5: Implement `GET /internal/vpn-endpoint-monitor/targets`**

Return bounded JSON. Normalize host/port/type/transport/IKE fields. Invalid records become an omitted/disabled safe item rather than leaking diagnostics.

- [ ] **Step 6: Write failing result-contract tests**

Cover stale revision rejection, unknown VPN, inactive VPN, invalid outcome/code/probe type/latency/timestamp, oversized arrays, duplicate IDs, and valid transition storage.

- [ ] **Step 7: Implement `POST /internal/vpn-endpoint-monitor/results`**

Validate the complete batch before applying it or use one transaction with deterministic per-row status; prefer all-or-nothing for malformed batches. Return only counts and normalized rejection codes.

- [ ] **Step 8: Run focused API and health tests and verify GREEN**

## Task 3: Implement protocol-aware probes and destination policy

**Files:**
- Create: `panel-app/vpn_endpoint_monitor.py`
- Create: `tests/test_vpn_endpoint_monitor.py`

- [ ] **Step 1: Write failing DNS/policy tests**

Cover IPv4/IPv6 global unicast acceptance; rejection of loopback, private, link-local, CGNAT, multicast, unspecified, and reserved addresses; mixed DNS answers; DNS timeout/failure; and no probe call for forbidden destinations.

- [ ] **Step 2: Run focused worker tests and verify RED**

Expected: missing worker module.

- [ ] **Step 3: Implement safe resolution and target validation**

Inject resolver/clock/runner dependencies for tests. Resolve with bounded timeout where supported, de-duplicate results, and never include resolved addresses in posted diagnostics.

- [ ] **Step 4: Write failing TCP probe tests**

Cover any-address success, all-address refusal/timeout/unreachable, bounded latency, SSL/OpenVPN-TCP/PPTP mapping, and no endpoint banner reads.

- [ ] **Step 5: Implement bounded TCP connect probes**

Use `socket.create_connection`/explicit sockets with a three-second deadline and close every socket in `finally`/context managers.

- [ ] **Step 6: Write failing IKE command/result tests**

Cover IKEv1, aggressive IKEv1, IKEv2, NAT-T/4500, source port behavior, command argument allowlisting, timeout, a normalized valid IKE response, and zero raw output in the result DTO.

- [ ] **Step 7: Implement the `ike-scan` adapter**

Use argv arrays only (`shell=False`), explicit `--retry`, `--timeout`, `--sport=0`, and supported version/mode flags. Accept a protocol response based on strict output classification; normalize silence/tool failure separately.

- [ ] **Step 8: Write failing OpenVPN-UDP tests**

Require explicit response → reachable, explicit ICMP port unreachable → unreachable, silence → inconclusive. If no reliable protocol-specific packet is implemented, keep UDP silence inconclusive and document that limitation.

- [ ] **Step 9: Implement dispatcher and normalized result DTO**

- [ ] **Step 10: Run focused worker tests and verify GREEN**

## Task 4: Implement the five-minute worker loop and least-privilege image

**Files:**
- Modify: `panel-app/vpn_endpoint_monitor.py`
- Create: `images/vpn-endpoint-monitor/Dockerfile`
- Modify: `panel-app/Dockerfile` only if shared modules must be copied for the panel.
- Extend: `tests/test_vpn_endpoint_monitor.py`

- [ ] **Step 1: Write failing API-client and cycle tests**

Cover token-file auth, immediate first cycle, 300-second interval, bounded jitter, max four concurrent probes, bounded response size, failed panel request without unbounded queue, and next-cycle recovery.

- [ ] **Step 2: Run tests and verify RED**

- [ ] **Step 3: Implement stdlib HTTP client and cycle orchestration**

Use `urllib.request`, strict JSON size/schema checks, `ThreadPoolExecutor(max_workers=4)`, monotonic scheduling, and bounded backoff. Never log target hostnames or result payloads.

- [ ] **Step 4: Add a CLI entry point**

Support `--once` for tests/canaries and defaults `--interval 300 --workers 4 --timeout 3` with safe minimum/maximum bounds.

- [ ] **Step 5: Build the monitor image contract**

Use a pinned base digest, install only `ike-scan` and required certificates, create a non-root user, copy only the worker, use read-only-compatible paths, and no Docker CLI.

- [ ] **Step 6: Run unit tests and build the image**

Verify `ike-scan --version` inside the image and an offline `--once` failure mode that exits/loops predictably without secrets in output.

## Task 5: Compose, secret, and Caddy integration

**Files:**
- Create: `tests/test_vpn_endpoint_monitor_integration.py`
- Modify: `docker-compose.yml`
- Modify: `caddy/Caddyfile`
- Modify: `.env.example`

- [ ] **Step 1: Write failing static integration tests**

Assert:

- monitor uses immutable `${MONITOR_IMAGE:?...}`;
- no Docker socket, panel-data volume, project volume, privileged mode, host network, or published port;
- read-only filesystem, non-root user, `cap_drop: ALL`, `no-new-privileges`, bounded tmpfs;
- panel and monitor mount the same external token file as a read-only secret;
- monitor interval is 300 seconds;
- Caddy answers `/internal/*` without proxying to panel;
- the panel remains the only service with database and Docker access needed by existing behavior.

- [ ] **Step 2: Run integration tests and verify RED**

- [ ] **Step 3: Modify Compose, Caddy, and environment contract minimally**

Do not add a real token or deployment path. Add `MONITOR_IMAGE` and `VPN_ENDPOINT_MONITOR_TOKEN_FILE` placeholders only.

- [ ] **Step 4: Run Compose with synthetic values and verify GREEN**

```bash
docker compose -f docker-compose.yml config --quiet
```

- [ ] **Step 5: Run static integration tests and verify GREEN**

## Task 6: Render correlated alerts for authorized users and admin diagnostics

**Files:**
- Create: `tests/test_vpn_endpoint_monitor_ui.py`
- Modify: `panel-app/app.py`
- Possibly extend: `tests/test_access_panel_redesign.py`

- [ ] **Step 1: Write failing ordinary-user card tests**

Assert alert appears only when:

- endpoint state is `down`;
- at least two failures are stored;
- runtime/tunnel is offline;
- the user is authorized for that site.

Assert no hostname, address, port, probe command, raw code, or latency appears to ordinary users.

- [ ] **Step 2: Verify RED**

- [ ] **Step 3: Implement a small health DTO/query helper and card alert markup**

Keep the card compact. Add accessible `role=status`/semantic alert text and dark/light CSS using existing tokens.

- [ ] **Step 4: Write failing precedence/recovery tests**

Cover online tunnel suppressing the ordinary alert, suspect/unknown/stale states suppressing the ordinary alert, and healthy recovery removing it.

- [ ] **Step 5: Implement precedence logic and verify GREEN**

- [ ] **Step 6: Write failing administrator VPN-table tests**

Require state, probe type, failures, last check, last success, latency, and normalized explanation. Permit the already-visible endpoint only on the admin route.

- [ ] **Step 7: Implement admin diagnostics and verify GREEN**

- [ ] **Step 8: Run all UI regression tests**

Ensure existing plant-first cards, sortable equipment tables, persistent theme, and VPN runtime status remain unchanged apart from the new warning.

## Task 7: Documentation and operator runbook

**Files:**
- Modify: `README.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/CONFIGURATION.md`
- Modify: `docs/SECURITY.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Document evidence semantics and limitations**

State explicitly that public endpoint health is not tunnel health, TCP/1723 does not prove GRE, and UDP silence can be inconclusive.

- [ ] **Step 2: Document configuration**

Include external token-file creation requirements without showing a live value, immutable monitor image, five-minute interval, two-failure threshold, and no automatic actions.

- [ ] **Step 3: Document deployment/rollback**

Panel migration → Caddy policy → token file → monitor canary → two observed cycles → UI enablement; rollback removes monitor and reverts image references without touching VPN containers.

- [ ] **Step 4: Run Markdown, links, spelling, YAML, and secret-pattern checks**

## Task 8: Full verification and independent review

**Files:** all changed files.

- [ ] **Step 1: Run focused new tests in Linux**

```bash
PYTHONPATH=panel-app python -m unittest -v \
  tests/test_vpn_endpoint_health.py \
  tests/test_vpn_endpoint_monitor.py \
  tests/test_vpn_endpoint_monitor_api.py \
  tests/test_vpn_endpoint_monitor_ui.py \
  tests/test_vpn_endpoint_monitor_integration.py
```

Expected: all pass.

- [ ] **Step 2: Run the complete Linux suite**

```bash
PYTHONPATH=panel-app python tests/run_full_suite.py
```

Expected: zero failures and zero exclusions.

- [ ] **Step 3: Run static/build gates**

- `python -m compileall -q panel-app tests`
- `git diff --check`
- synthetic `docker compose config --quiet`
- build monitor image
- run monitor unit smoke in the built image
- ShellCheck all shell scripts
- CLIPRDR contract
- Gitleaks on tree and complete feature-branch history
- protected-path/configured-site/private-address audits

- [ ] **Step 4: Stage the diff and run pre-commit security review**

Use the `requesting-code-review` skill: static scan, baseline-aware tests, self-review, independent reviewer, and at most two focused fix cycles.

- [ ] **Step 5: Commit verified implementation**

Use focused commits or one verified feature commit after all gates. Do not commit deployment tokens, generated configs, databases, or test artifacts.

## Task 9: Publish feature branch and merge through protected GitHub main

**Files:** Git/GitHub state only.

- [ ] **Step 1: Push `feature/vpn-endpoint-monitoring`**

- [ ] **Step 2: Open a PR with design link, behavior matrix, test evidence, security boundaries, deployment plan, and rollback**

- [ ] **Step 3: Wait for all seven existing checks plus new feature tests to complete successfully**

- [ ] **Step 4: Merge without bypassing protected-branch checks**

- [ ] **Step 5: Verify public `main` SHA/tree/history and pull exact merged SHA into `/opt/plantas-vpn-bastion-git`**

## Task 10: Fail-closed production canary and promotion

**Files:** production deployment inputs outside Git; no secrets printed.

- [ ] **Step 1: Capture rollback state**

Record exact immutable panel/Caddy/monitor image references, container identities/restart counts, Compose configuration hashes, database backup handle/checksum, disk space, and current service health without dumping environments or database values.

- [ ] **Step 2: Build immutable panel and monitor images from the merged public SHA**

Tag by release/SHA, inspect image IDs/digests, and run the full candidate validation against exact image identities.

- [ ] **Step 3: Validate token file and migration in an isolated copy**

Create the monitor token through the approved secret path, mode `0600`, never display it. Exercise schema migration against a protected database copy before production.

- [ ] **Step 4: Deploy panel/Caddy policy with monitor disabled**

Verify login, admin VPN page, site cards, RDP/WEB routes, Guacamole health, container identity, and no secret exposure.

- [ ] **Step 5: Start monitor in canary mode**

Use one synthetic/approved non-customer endpoint or one explicitly selected active VPN without displaying its address. Run `--once`, verify normalized result and no VPN/container mutation.

- [ ] **Step 6: Enable scheduled monitoring and observe two complete five-minute cycles**

Verify result timestamps/counters, stale handling, ordinary-user redaction, admin detail, CPU/RAM, logs, and zero VPN restarts or container identity changes.

- [ ] **Step 7: Verify diagnostic matrix live**

Use controlled test data or temporary synthetic record—not a customer outage—to prove first failure has no user alert, second failure shows the authorized-site alert, online tunnel suppresses it, and success clears it.

- [ ] **Step 8: Promote or roll back**

Promote only if all canary gates pass. Otherwise stop monitor, revert panel/Caddy image references, restore the DB backup only if schema rollback requires it, and verify original container identities/services.

- [ ] **Step 9: Final production verification**

Confirm the deployed merged SHA/image identities, 5-minute schedule, all core services healthy, no restarting containers, no VPN/equipment state mutation, and no secrets in logs/UI.
