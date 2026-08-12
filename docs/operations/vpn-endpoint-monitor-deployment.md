# VPN endpoint monitor deployment

This runbook promotes the endpoint monitor without broad changes to the VPN
data planes. Keep collection, admin diagnostics, and public alerts disabled
until their individual gates pass.

## Compatibility and migration order

1. Record the reviewed commit, immutable image digests, active container IDs,
   current maximum cycle, and `PRAGMA integrity_check` result.
2. Take a protected **database backup** using the SQLite backup API or
   `sqlite3 .backup`; never copy a live WAL database as loose files.
3. Validate the backup with `PRAGMA integrity_check` in an isolated location.
4. Promote the **panel first**. Its schema migration is additive and
   idempotent, accepts the previous monitor contract during the transition,
   and rejects stale `target_revision` results without partial writes.
5. Run the migration twice against a disposable copy to prove idempotency, then
   start the panel against the persistent volume and verify existing VPN rows.
6. Promote the monitor only after panel readiness and internal API smoke tests
   pass. Use `docker compose up -d --no-deps --force-recreate panel
   vpn-endpoint-monitor`; do not recreate VPN, Caddy, Guacamole, guacd, or
   reconciler containers.
7. Wait for **one complete cycle** newer than the pre-deployment cycle before
   enabling diagnostics or expanding the target selector.

The legacy health schema is rebuilt inside one immediate transaction. Legacy
rows are normalized to `accessible` or `unreachable`; transition events remain
separate. Recovery is restoration of the verified database backup and previous
immutable images, not a destructive down-migration.

### Migration recovery drill

The migration is intentionally forward-only. Before the panel is promoted,
exercise the recovery boundary on a disposable copy:

```bash
sqlite3 /path/to/panel.db ".backup '/tmp/panel.db.pre-monitor'"
sqlite3 /tmp/panel.db.pre-monitor "PRAGMA integrity_check;"
# Run the panel migration twice against a disposable copy.
sqlite3 /tmp/panel.db.pre-monitor "PRAGMA integrity_check;"
```

The expected result is `ok` after both runs, with the original `vpns` rows
unchanged and the endpoint-health tables present. If a real promotion fails,
stop only `panel` and `vpn-endpoint-monitor`, restore the verified backup using
the approved SQLite backup procedure, and then restore the previous immutable
images. Never attempt an ad-hoc `ALTER TABLE` rollback on the live database.

## Token generation and token rotation

Generate the monitor token outside Git with at least 32 random printable bytes.
Install the source file as root-owned with group-only read access for the
monitor worker. File-backed Compose secrets may ignore requested mount
ownership, so verify readability with the exact non-root image before
promotion without printing the token.

A **token rotation** is coordinated because the API supports one token at a
time:

1. Create a new protected token file and verify its ownership and mode.
2. Point the deployment environment at the new file.
3. Recreate panel and monitor together with `--no-deps`.
4. Verify unauthenticated requests remain indistinguishable `404`, the new
   monitor completes one cycle, and restart counts stay stable.
5. Securely remove the old token only after acceptance.

## Canary and gradual rollout

1. Keep `VPN_ENDPOINT_PUBLIC_ALERTS_ENABLED=false`.
2. Set `VPN_ENDPOINT_MONITOR_TARGET_IDS` to controlled canary IDs covering TCP,
   OpenVPN UDP, IKEv1, IKEv1 Aggressive, IKEv2, NAT-T, and PPTP where available.
3. Verify the host egress policy independently, including denied private and
   reserved destinations.
4. Observe several cycles; compare normalized results with approved manual
   checks and record false-positive/false-negative analysis.
5. Measure cycle duration, CPU, memory, process count, restart count, and SQLite
   growth. The cycle must finish comfortably inside 60 seconds.
6. Validate Admin list/detail/history and all tunnel/endpoint combinations in
   the user panel before broadening collection and finally enabling alerts.

Logs may contain only normalized codes, IDs, cycle metadata, and bounded timing.
Never collect raw `ping` or `ike-scan` output, endpoint inventories, credentials,
or packet payloads.

## Toolchain verification

The monitor image pins the Debian package `ike-scan=1.9.5-2` and includes
`iputils-ping`. Verify the exact package versions before promotion:

```bash
docker run --rm --entrypoint sh "$MONITOR_IMAGE" -c \
  'dpkg-query -W -f="${Package}=${Version}\\n" ike-scan iputils-ping'
```

The output must contain `ike-scan=1.9.5-2`. A different package version or a
changed image digest invalidates the reviewed promotion bundle.

## Rollback

Rollback when migration, API, security, persistence, UI, or cycle gates fail:

1. Disable public alerts and collection.
2. Preserve normalized evidence and the failed image hashes.
3. Restore the previous panel and monitor immutable images with `--no-deps`.
4. If schema/data integrity failed, stop only panel and monitor, restore the
   verified database backup, and restart those services only.
5. Verify `integrity_check`, panel readiness, unchanged protected container IDs,
   stable restart counts, and one complete cycle on the previous version.

Any change to an approved bundle invalidates its promotion authorization.
