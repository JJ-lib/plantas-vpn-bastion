# Cabrovales Minimal WEB Onboarding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a minimal automatic WEB onboarding flow for new Cabrovales equipment while preserving the legacy flow and runtime behavior for every other plant.

**Architecture:** Keep the existing SQLite/Flask and HAProxy publication boundaries. Add an explicit plant onboarding profile, store the detected upstream transport/Host/SNI alongside the existing WEB mode, and make the Cabrovales new-equipment route use a preflight → staged render → validation → scoped publication transaction. Backport the production certificate-mount fix into the repository before adding automatic onboarding.

**Tech Stack:** Python 3, Flask, SQLite, HAProxy, Docker Compose, unittest, pinned Docker image.

---

## Task 1: Reconcile the production TLS hotfix into the repository

**Files:**
- Modify: `panel-app/app.py` near `write_ipsec_compose()`.
- Create: `tests/test_bridge_ipsec_compose.py`.

- [ ] **Step 1: Write the regression test**

Create a temporary SQLite database and project directory, insert one `WEB` row for a plant with `web_mode='direct'`, render the IPsec Compose, and assert that the common certificate mount is absent. Update the same row to `web_mode='bridge_tls'` and `web_effective_mode='bridge_tls'`, render again, and assert exactly one mount:

```text
./configs/bridge.pem:/etc/haproxy/certs/bridge.pem:ro
```

- [ ] **Step 2: Run the focused test and observe the failure**

Run:

```bash
python tests/test_bridge_ipsec_compose.py
```

Expected on `main`: failure because `write_ipsec_compose()` does not inspect the plant WEB mode or add the certificate mount.

- [ ] **Step 3: Implement the minimal hotfix**

Add:

```python
def plant_uses_bridge_tls(slug):
    row = db().execute(
        """SELECT 1 FROM vpns v JOIN equipment e ON e.plant=v.plant
           WHERE v.slug=? AND e.active=1 AND e.kind='WEB'
             AND (e.web_mode='bridge_tls' OR e.web_effective_mode='bridge_tls')
           LIMIT 1""",
        (slug,),
    ).fetchone()
    if not row:
        return False
    cert = os.path.join(BASE, 'configs', 'bridge.pem')
    if not os.path.isfile(cert):
        raise ValueError(f'Falta el certificado TLS del bastión para la planta {slug}.')
    return True
```

Use the result in `write_ipsec_compose()` to add the common mount only when needed. Do not hard-code `puerto-real-4` or `cabrovales` into the generator.

- [ ] **Step 4: Run the focused test**

Run:

```bash
python tests/test_bridge_ipsec_compose.py
```

Expected: `1 test ... OK`.

## Task 2: Add an explicit plant onboarding profile and persisted upstream facts

**Files:**
- Modify: `panel-app/app.py` schema migration and equipment migration helpers.
- Create or modify: `tests/test_cabrovales_web_onboarding.py`.

- [ ] **Step 1: Add schema assertions first**

Extend the existing idempotent migrations with these columns:

```sql
ALTER TABLE vpns ADD COLUMN web_onboarding_profile TEXT DEFAULT 'legacy';
ALTER TABLE vpns ADD COLUMN web_default_host TEXT DEFAULT '';
ALTER TABLE equipment ADD COLUMN web_upstream_scheme TEXT DEFAULT '';
ALTER TABLE equipment ADD COLUMN web_upstream_host TEXT DEFAULT '';
ALTER TABLE equipment ADD COLUMN web_validation_profile TEXT DEFAULT '';
ALTER TABLE equipment ADD COLUMN web_validation_state TEXT DEFAULT 'unvalidated';
```

The migration must tolerate already-present columns and must never rewrite existing equipment modes. Add a helper that returns `legacy` for every plant except an explicit `minimal_auto` profile. The Cabrovales profile is enabled by an explicit persisted setting, not by a global IP allowlist.

- [ ] **Step 2: Add tests for profile isolation**

Assert that:

- A temporary database defaults a plant to `legacy`.
- Cabrovales can be set to `minimal_auto` with `web_default_host='local.domain'`.
- A second plant remains `legacy`.
- Existing `web_mode`, `web_effective_mode`, and `web_proxy_port` values survive migration unchanged.

- [ ] **Step 3: Run the schema/profile test and observe the failure**

Run:

```bash
python tests/test_cabrovales_web_onboarding.py
```

Expected on the unmodified branch: failure because the profile and upstream columns do not exist.

- [ ] **Step 4: Implement the idempotent migration and profile helper**

Use the existing migration style in `init()` and add a helper with this contract:

```python
def web_onboarding_profile(plant):
    """Return ('legacy'|'minimal_auto', default_host) for one plant."""
```

Do not enable `minimal_auto` for another plant as a side effect of migration.

- [ ] **Step 5: Run the profile test**

Expected: all profile and migration assertions pass.

## Task 3: Implement automatic Cabrovales preflight classification

**Files:**
- Modify: `panel-app/app.py` near `probe_web_equipment()`, `analyze_web_probe()`, and `finalize_web_settings()`.
- Modify: `tests/test_cabrovales_web_onboarding.py`.

- [ ] **Step 1: Add failing classifier tests**

Use an injected runner; never call a real device in unit tests. Cover these inputs:

1. HTTP `200` with relative URLs → `generic_http`, upstream scheme `http`, empty upstream host.
2. HTTPS `200` with no private absolute URLs → `generic_https`, upstream scheme `https`, empty upstream host.
3. Default probes fail but HTTPS with `local.domain` succeeds → `plant_host_https`, upstream scheme `https`, host `local.domain`.
4. HTML or `Location` contains the private IP → `private_urls` and the existing rewrite strategy.
5. Both schemes fail → `unreachable`, and `finalize_web_settings()` raises without returning a publishable result.

- [ ] **Step 2: Run the new tests to verify they fail**

Run:

```bash
python tests/test_cabrovales_web_onboarding.py -k preflight
```

Expected: failure because the current probe only chooses HTTP/HTTPS from port 443 and does not test plant Host/SNI candidates.

- [ ] **Step 3: Implement the probe contract**

Add an injected-runner function that:

- Executes `curl` only through `docker exec vpn-<slug>`.
- Tests HTTP and HTTPS with bounded timeouts.
- Uses `--insecure` only for the internal device leg.
- Tries the persisted plant host candidate with `Host` and HTTPS SNI when applicable.
- Reads headers and at most 512 KiB of body.
- Returns only classification, status, scheme, host, private-URL count, and diagnostic; never stores HTML or credentials.

Keep legacy `direct` and `rewrite_cache` behavior unchanged for plants with profile `legacy`.

- [ ] **Step 4: Connect the classifier to `finalize_web_settings()`**

For a new WEB record in Cabrovales `minimal_auto`:

- Set the public strategy to bastion TLS (`bridge_tls`).
- Store `web_upstream_scheme`, `web_upstream_host`, `web_validation_profile`, and `web_validation_state='validated'`.
- Set `web_proxy_port` only for the existing rewrite sidecar.
- Reject `unreachable` before the SQLite insert.

For all other plants, retain the current `web_mode`/`auto` flow byte-for-byte where possible.

- [ ] **Step 5: Run the focused preflight tests**

Expected: all five classifier cases pass and legacy mode tests remain green.

## Task 4: Render HTTP, HTTPS, and Host/SNI backends safely

**Files:**
- Modify: `panel-app/app.py` in `render_haproxy_for_plant()` and related target helpers.
- Modify: `tests/test_cabrovales_web_onboarding.py`.
- Reuse: `tests/test_web_publication_mode.py`.

- [ ] **Step 1: Add renderer contract tests**

Assert generated HAProxy for new Cabrovales rows has:

- `bind *:<public_port> ssl crt /etc/haproxy/certs/bridge.pem` for all automatic public WEB entries.
- Backend `server target <ip>:<port>` with no `ssl` for `generic_http`.
- Backend `server target <ip>:<port> ssl verify none` for `generic_https`.
- Backend HTTPS plus `sni str(local.domain)` and Host rewrite for `plant_host_https`.
- Existing direct/rewrite rows render exactly as before.

- [ ] **Step 2: Run the renderer tests to verify the failure**

Run:

```bash
python tests/test_cabrovales_web_onboarding.py -k render
python tests/test_web_publication_mode.py
```

Expected: new renderer assertions fail on `main`; existing tests establish the legacy baseline.

- [ ] **Step 3: Implement the renderer change**

Use the stored upstream scheme/host only for rows created by `minimal_auto`. Do not infer HTTPS solely from port `443`. Never add backend `ssl` to an HTTP upstream. Keep the common certificate path constant and require the Compose mount when any active plant WEB row uses public bridge TLS.

- [ ] **Step 4: Run renderer and legacy tests**

Expected: automatic renderer assertions and all existing WEB mode tests pass.

## Task 5: Reduce the Cabrovales new-WEB form and add publish smoke validation

**Files:**
- Modify: `panel-app/app.py` form renderer and `/admin/equipment/new` route.
- Modify: `tests/test_cabrovales_web_onboarding.py`.

- [ ] **Step 1: Add form/rollback tests**

Assert that:

- New WEB in Cabrovales shows only name, real IP, and real port plus the existing plant context/tags required by the application.
- New WEB in a legacy plant still shows the current form.
- A failed preflight creates no `equipment` row.
- A staged Compose or HAProxy failure rolls back the candidate row and leaves the previous artifact hashes unchanged.

- [ ] **Step 2: Implement the feature-gated form**

Pass a `minimal_web_onboarding` flag into the existing form renderer only from the Cabrovales new-WEB route. Keep edit and all non-Cabrovales routes on the legacy form until the pilot is accepted. Use server-side values for the profile; ignore hidden legacy mode/host fields in the minimal route.

- [ ] **Step 3: Add scoped public smoke validation**

After the staged Compose and HAProxy checks but before the database savepoint is released, validate the new public port from the bastion host with a bounded HTTP request. Require a response status in `200..399` and verify that the expected port belongs to the newly rendered row. On failure, invoke the existing file/runtime rollback path.

- [ ] **Step 4: Run the form and rollback tests**

Expected: minimal Cabrovales form, legacy form isolation, no-row-on-failure, and artifact rollback all pass.

## Task 6: Local quality gates and candidate image

**Files:**
- No production files; use repository source and tests.

- [ ] **Step 1: Run focused tests**

```bash
python tests/test_bridge_ipsec_compose.py
python tests/test_cabrovales_web_onboarding.py
python tests/test_web_publication_mode.py
```

- [ ] **Step 2: Run repository test discovery**

Use the project’s documented test command or, if none exists:

```bash
python -m unittest discover -s tests -p 'test_*.py'
```

- [ ] **Step 3: Compile and inspect the diff**

```bash
python -m py_compile panel-app/app.py
 git diff --check
 git status --short
```

The diff must contain only the TLS backport, Cabrovales onboarding code/tests, the design, and the implementation plan.

- [ ] **Step 4: Build the candidate panel image**

Build from the repository branch using the pinned Dockerfile bases and a unique candidate tag. Run the focused tests inside that image before remote promotion.

## Task 7: Scoped remote pilot promotion and verification

**Files:**
- Remote deployment only after local gates pass.

- [ ] **Step 1: Capture remote baseline and backup**

Record hashes of source, Compose, Cabrovales HAProxy/Compose, panel DB, panel image, and IDs/restart counts for unrelated containers. Store an exclusive backup directory and verify it before any write.

- [ ] **Step 2: Promote only the panel candidate**

Use the repository-built digest and `up -d --no-deps --force-recreate --pull never panel`. Do not use `--remove-orphans` and do not recreate other plant services yet.

- [ ] **Step 3: Enable the Cabrovales profile only**

Set the explicit Cabrovales profile and default host in the panel DB using a transaction, verify the other plants remain `legacy`, and read back the exact row.

- [ ] **Step 4: Add one non-critical WEB test equipment**

Use the minimal form for one authorized test endpoint in Cabrovales. Verify the classifier, generated HAProxy, Compose certificate mount, scoped container IDs, public HTTP status, and saved diagnostic. Do not modify the existing 32 WEB rows.

- [ ] **Step 5: Test failure rollback**

Use a controlled unreachable test input or injected staging failure. Verify no equipment row, no artifact change, no unrelated container restart, and a clear UI diagnostic.

- [ ] **Step 6: Report evidence and stop before widening scope**

Leave every other plant on the legacy profile. Do not push or merge the branch until the user reviews the pilot evidence.
