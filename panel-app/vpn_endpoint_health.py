"""Persistent, deterministic health state for public VPN endpoints.

The panel owns this module and is the only component allowed to write health
state.  A successful cycle is ``icmp_ok or protocol_ok``; only three complete
failures move a public endpoint to ``unreachable``.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Mapping


HEALTH_STATES = frozenset({"accessible", "unreachable"})
PROBE_TYPES = frozenset({"tcp", "ike", "openvpn_udp"})
VPN_TYPES = frozenset({"ssl", "ipsec", "pptp", "openvpn"})
TRANSPORTS = frozenset({"tcp", "udp"})
IKE_VERSIONS = frozenset({"ikev1", "ikev2"})
MAX_CONSECUTIVE_FAILURES = 255
FAILURE_THRESHOLD = 3
HISTORY_HOURS = 5
HISTORY_SECONDS = HISTORY_HOURS * 60 * 60
STALE_AFTER_SECONDS = 15 * 60
MAX_LATENCY_MS = 60_000
MAX_TIMESTAMP = 253_402_300_799
MAX_VPN_ID = 2**63 - 1
MAX_TARGET_GENERATION = 2**63 - 1
MAX_CYCLE_ID = 2**63 - 1
MAX_LEASE_ID_LENGTH = 128
MAX_HEALTH_QUERY_IDS = 500

RESULT_REQUIRED_FIELDS = frozenset(
    {"vpn_id", "target_revision", "icmp_ok", "protocol_ok", "protocol_probe", "checked_at"}
)
RESULT_OPTIONAL_FIELDS = frozenset(
    {
        "icmp_code",
        "protocol_code",
        "latency_ms",
        "target_generation",
        "cycle_id",
        "lease_id",
    }
)
RESULT_FIELDS = RESULT_REQUIRED_FIELDS | RESULT_OPTIONAL_FIELDS
_REVISION_RE = re.compile(r"[0-9a-f]{64}\Z")
_CODE_RE = re.compile(r"[a-z0-9_]{1,64}\Z")
_CODES = frozenset(
    {
        "not_checked",
        "icmp_reply",
        "icmp_timeout",
        "icmp_unreachable",
        "icmp_probe_error",
        "tcp_accept",
        "tcp_unreachable",
        "ike_response",
        "ike_no_response",
        "ike_unreachable",
        "openvpn_udp_response",
        "udp_port_unreachable",
        "udp_silent",
        "dns_failed",
        "dns_timeout",
        "dns_no_answers",
        "dns_no_global_address",
        "private_or_reserved_destination",
        "probe_error",
        "unsupported_probe",
    }
)

_HEALTH_COLUMNS = (
    "vpn_id",
    "target_revision",
    "target_generation",
    "cycle_id",
    "lease_id",
    "state",
    "consecutive_failures",
    "icmp_ok",
    "protocol_ok",
    "protocol_probe",
    "icmp_code",
    "protocol_code",
    "last_checked_at",
    "last_success_at",
    "last_transition_at",
    "updated_at",
    "latency_ms",
)
_HEALTH_COLUMN_SQL = ",".join(_HEALTH_COLUMNS)


class StaleRevisionError(ValueError):
    """A result describes a target configuration that is no longer current."""


class StaleCycleError(ValueError):
    """A result belongs to an older or conflicting monitor cycle."""


def _mapping_keys(value: Any) -> set[str]:
    if not hasattr(value, "keys") or not callable(value.keys):
        raise ValueError("Expected a mapping.")
    try:
        return set(value.keys())
    except (TypeError, ValueError) as exc:
        raise ValueError("Expected a mapping.") from exc


def _required(mapping: Any, key: str) -> Any:
    try:
        return mapping[key]
    except (KeyError, TypeError, IndexError) as exc:
        raise ValueError(f"Missing required field: {key}.") from exc


def _strict_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer.")
    if not minimum <= value <= maximum:
        raise ValueError(f"{label} is outside the accepted range.")
    return value


def _strict_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be boolean.")
    return value


def _enum(value: Any, label: str, values: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in values:
        raise ValueError(f"Invalid {label}.")
    return value


def _port(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("port must be an integer.")
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and value.isascii() and value.isdigit():
        port = int(value, 10)
    else:
        raise ValueError("port must be an integer.")
    if not 1 <= port <= 65_535:
        raise ValueError("port is outside the accepted range.")
    return port


def _revision(value: Any) -> str:
    if not isinstance(value, str) or not _REVISION_RE.fullmatch(value):
        raise ValueError("Invalid target revision.")
    return value


def _lease(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_LEASE_ID_LENGTH
        or not value.isascii()
    ):
        raise ValueError("Invalid lease_id.")
    return value


def _timestamp(value: Any, label: str = "checked_at") -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be an epoch integer or UTC ISO-8601 value.")
    if isinstance(value, int):
        return _strict_int(value, label, 0, MAX_TIMESTAMP)
    if not isinstance(value, str) or not value.isascii():
        raise ValueError(f"{label} must be an epoch integer or UTC ISO-8601 value.")
    text = value.strip()
    if not text.endswith("Z"):
        raise ValueError(f"{label} must use UTC (Z).")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} is invalid.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{label} must use UTC.")
    return _strict_int(int(parsed.timestamp()), label, 0, MAX_TIMESTAMP)


def target_revision(config: Any) -> str:
    """Hash only canonical, non-secret fields that change a public probe."""
    keys = _mapping_keys(config)
    required = {"vpn_type", "host", "port", "transport"}
    if not required <= keys:
        raise ValueError("Missing probe configuration.")

    vpn_type = _enum(str(_required(config, "vpn_type")).strip().lower(), "vpn_type", VPN_TYPES)
    host_raw = _required(config, "host")
    if not isinstance(host_raw, str):
        raise ValueError("Invalid host.")
    host = host_raw.strip().lower().rstrip(".")
    if not 1 <= len(host) <= 253 or any(ord(ch) < 33 or ord(ch) == 127 for ch in host):
        raise ValueError("Invalid host.")
    transport = _enum(str(_required(config, "transport")).strip().lower(), "transport", TRANSPORTS)
    canonical: dict[str, Any] = {
        "vpn_type": vpn_type,
        "host": host,
        "port": _port(_required(config, "port")),
        "transport": transport,
        "ike_version": "",
        "aggressive": False,
        "nat_t": False,
    }
    if vpn_type == "ipsec":
        ike = _enum(str(config.get("ike_version", "ikev1")).strip().lower(), "ike_version", IKE_VERSIONS)
        aggressive = config.get("aggressive", False)
        nat_t = config.get("nat_t", config.get("nat_traversal", False))
        if not isinstance(aggressive, bool) or not isinstance(nat_t, bool):
            raise ValueError("IKE mode flags are invalid.")
        canonical.update(ike_version=ike, aggressive=aggressive if ike == "ikev1" else False, nat_t=nat_t)
    elif "aggressive" in keys and not isinstance(config["aggressive"], bool):
        raise ValueError("aggressive must be boolean.")

    payload = json.dumps(canonical, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _normalise_code(value: Any, label: str, default: str) -> str:
    if value is None:
        return default
    if not isinstance(value, str) or not _CODE_RE.fullmatch(value) or value not in _CODES:
        raise ValueError(f"Invalid {label}.")
    return value


def validate_result(result: Any) -> dict[str, Any]:
    """Validate the minimal public result contract and return a safe copy."""
    keys = _mapping_keys(result)
    if not RESULT_REQUIRED_FIELDS <= keys or not keys <= RESULT_FIELDS:
        raise ValueError("Result fields do not match the endpoint-health contract.")
    probe = _enum(_required(result, "protocol_probe"), "protocol_probe", PROBE_TYPES)
    normalized: dict[str, Any] = {
        "vpn_id": _strict_int(_required(result, "vpn_id"), "vpn_id", 1, MAX_VPN_ID),
        "target_revision": _revision(_required(result, "target_revision")),
        "icmp_ok": _strict_bool(_required(result, "icmp_ok"), "icmp_ok"),
        "protocol_ok": _strict_bool(_required(result, "protocol_ok"), "protocol_ok"),
        "protocol_probe": probe,
        "checked_at": _timestamp(_required(result, "checked_at")),
        "icmp_code": _normalise_code(result.get("icmp_code"), "icmp_code", "icmp_reply" if result["icmp_ok"] else "icmp_timeout"),
        "protocol_code": _normalise_code(result.get("protocol_code"), "protocol_code", "probe_error" if not result["protocol_ok"] else "tcp_accept"),
        "latency_ms": None,
        "target_generation": 0,
        "cycle_id": 0,
        "lease_id": "",
    }
    if "latency_ms" in keys and result["latency_ms"] is not None:
        normalized["latency_ms"] = _strict_int(result["latency_ms"], "latency_ms", 0, MAX_LATENCY_MS)
    if "target_generation" in keys:
        normalized["target_generation"] = _strict_int(result["target_generation"], "target_generation", 0, MAX_TARGET_GENERATION)
    if "cycle_id" in keys:
        normalized["cycle_id"] = _strict_int(result["cycle_id"], "cycle_id", 0, MAX_CYCLE_ID)
    if "lease_id" in keys:
        normalized["lease_id"] = _lease(result["lease_id"])
    return normalized


def configure_sqlite_connection(conn: sqlite3.Connection) -> sqlite3.Connection:
    """Apply SQLite concurrency settings to every panel connection."""
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.DatabaseError:
        # In-memory databases and active transactions may not support WAL.
        pass
    return conn


@contextmanager
def _write_transaction(conn: sqlite3.Connection, savepoint: str):
    outer = conn.in_transaction
    conn.execute(f"SAVEPOINT {savepoint}" if outer else "BEGIN IMMEDIATE")
    try:
        yield
    except Exception:
        if outer:
            conn.execute(f"ROLLBACK TO {savepoint}")
            conn.execute(f"RELEASE {savepoint}")
        else:
            conn.rollback()
        raise
    else:
        if outer:
            conn.execute(f"RELEASE {savepoint}")
        else:
            conn.commit()


def _create_current_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS vpn_endpoint_health(
            vpn_id INTEGER PRIMARY KEY CHECK(vpn_id BETWEEN 1 AND 9223372036854775807),
            target_revision TEXT NOT NULL CHECK(length(target_revision)=64),
            target_generation INTEGER NOT NULL DEFAULT 0,
            cycle_id INTEGER NOT NULL DEFAULT 0,
            lease_id TEXT NOT NULL DEFAULT '',
            state TEXT NOT NULL CHECK(state IN ('accessible','unreachable')),
            consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK(consecutive_failures BETWEEN 0 AND 255),
            icmp_ok INTEGER CHECK(icmp_ok IN (0,1) OR icmp_ok IS NULL),
            protocol_ok INTEGER CHECK(protocol_ok IN (0,1) OR protocol_ok IS NULL),
            protocol_probe TEXT NOT NULL DEFAULT 'tcp',
            icmp_code TEXT NOT NULL DEFAULT 'not_checked',
            protocol_code TEXT NOT NULL DEFAULT 'not_checked',
            last_checked_at INTEGER CHECK(last_checked_at IS NULL OR last_checked_at BETWEEN 0 AND 253402300799),
            last_success_at INTEGER CHECK(last_success_at IS NULL OR last_success_at BETWEEN 0 AND 253402300799),
            last_transition_at INTEGER CHECK(last_transition_at IS NULL OR last_transition_at BETWEEN 0 AND 253402300799),
            updated_at INTEGER NOT NULL DEFAULT 0 CHECK(updated_at BETWEEN 0 AND 253402300799),
            latency_ms INTEGER CHECK(latency_ms IS NULL OR latency_ms BETWEEN 0 AND 60000)
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS vpn_endpoint_health_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vpn_id INTEGER NOT NULL,
            old_state TEXT NOT NULL CHECK(old_state IN ('accessible','unreachable')),
            new_state TEXT NOT NULL CHECK(new_state IN ('accessible','unreachable')),
            icmp_ok INTEGER CHECK(icmp_ok IN (0,1) OR icmp_ok IS NULL),
            protocol_ok INTEGER CHECK(protocol_ok IN (0,1) OR protocol_ok IS NULL),
            protocol_probe TEXT NOT NULL,
            icmp_code TEXT NOT NULL DEFAULT 'not_checked',
            protocol_code TEXT NOT NULL DEFAULT 'not_checked',
            created_at INTEGER NOT NULL CHECK(created_at BETWEEN 0 AND 253402300799)
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS ix_vpn_endpoint_health_events_vpn_id ON vpn_endpoint_health_events(vpn_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_vpn_endpoint_health_events_created_at ON vpn_endpoint_health_events(created_at)")


def _legacy_value(row: sqlite3.Row | tuple[Any, ...], columns: Mapping[str, int], name: str, default: Any = None) -> Any:
    if name not in columns:
        return default
    try:
        return row[name]  # type: ignore[index]
    except (IndexError, KeyError, TypeError):
        index = columns.get(name)
        return row[index] if index is not None and index < len(row) else default


def _migrate_legacy_health(conn: sqlite3.Connection, columns: Mapping[str, int]) -> None:
    """Migrate the previous multi-state table without touching VPN lifecycle data."""
    legacy_name = "vpn_endpoint_health_legacy_migration"
    if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (legacy_name,)).fetchone():
        conn.execute(f"DROP TABLE {legacy_name}")
    conn.execute(f"ALTER TABLE vpn_endpoint_health RENAME TO {legacy_name}")
    _create_current_schema(conn)
    rows = conn.execute(f"SELECT * FROM {legacy_name}").fetchall()
    now = int(time.time())
    for row in rows:
        vpn_id = _legacy_value(row, columns, "vpn_id")
        revision = _legacy_value(row, columns, "target_revision")
        if not isinstance(vpn_id, int) or not isinstance(revision, str) or not _REVISION_RE.fullmatch(revision):
            continue
        old_state = str(_legacy_value(row, columns, "state", "accessible"))
        state = "unreachable" if old_state in {"down", "unreachable"} else "accessible"
        probe = str(_legacy_value(row, columns, "protocol_probe", "tcp_connect"))
        probe = {"tcp_connect": "tcp", "openvpn_udp": "openvpn_udp", "ike": "ike"}.get(probe, "tcp")
        last_checked = _legacy_value(row, columns, "last_checked_at")
        if not isinstance(last_checked, int):
            last_checked = _legacy_value(row, columns, "observed_at")
        updated = last_checked if isinstance(last_checked, int) else now
        legacy_outcome = str(_legacy_value(row, columns, "outcome", ""))
        legacy_protocol_ok = _legacy_value(row, columns, "protocol_ok")
        if legacy_protocol_ok is None and legacy_outcome:
            legacy_protocol_ok = int(legacy_outcome == "reachable")
        legacy_protocol_code = _legacy_value(row, columns, "protocol_code")
        if legacy_protocol_code is None:
            legacy_protocol_code = _legacy_value(row, columns, "public_code", "not_checked")
        conn.execute(
            """INSERT INTO vpn_endpoint_health(
                vpn_id,target_revision,target_generation,cycle_id,lease_id,state,consecutive_failures,
                icmp_ok,protocol_ok,protocol_probe,icmp_code,protocol_code,last_checked_at,last_success_at,
                last_transition_at,updated_at,latency_ms
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                vpn_id,
                revision,
                int(_legacy_value(row, columns, "target_generation", 0) or 0),
                int(_legacy_value(row, columns, "cycle_id", 0) or 0),
                str(_legacy_value(row, columns, "lease_id", "legacy") or "legacy"),
                state,
                min(max(int(_legacy_value(row, columns, "consecutive_failures", 0) or 0), 0), MAX_CONSECUTIVE_FAILURES),
                _legacy_value(row, columns, "icmp_ok"),
                legacy_protocol_ok,
                probe,
                "not_checked",
                str(legacy_protocol_code or "not_checked")[:64],
                last_checked,
                _legacy_value(row, columns, "last_success_at"),
                _legacy_value(row, columns, "last_transition_at"),
                updated,
                _legacy_value(row, columns, "latency_ms"),
            ),
        )
    conn.execute(f"DROP TABLE {legacy_name}")


def ensure_endpoint_health_schema(conn: sqlite3.Connection) -> None:
    """Create/migrate health tables idempotently and atomically."""
    configure_sqlite_connection(conn)
    with _write_transaction(conn, "endpoint_health_schema"):
        row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vpn_endpoint_health'").fetchone()
        if row:
            columns = {item[1]: item[0] for item in conn.execute("PRAGMA table_info(vpn_endpoint_health)")}
            if "icmp_ok" not in columns or "updated_at" not in columns:
                _migrate_legacy_health(conn, columns)
            else:
                _create_current_schema(conn)
        else:
            _create_current_schema(conn)
        _create_current_schema(conn)


def _health_row(conn: sqlite3.Connection, vpn_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        f"SELECT {_HEALTH_COLUMN_SQL} FROM vpn_endpoint_health WHERE vpn_id=?",
        (vpn_id,),
    ).fetchone()
    return dict(zip(_HEALTH_COLUMNS, row)) if row is not None else None


def _purge_events(conn: sqlite3.Connection, cutoff: int) -> None:
    conn.execute("DELETE FROM vpn_endpoint_health_events WHERE created_at < ?", (cutoff,))


def apply_probe_result(
    conn: sqlite3.Connection,
    result: Any,
    *,
    expected_revision: str,
    expected_generation: int | None = None,
) -> dict[str, Any]:
    """Apply one result in one transaction and emit only state transitions."""
    normalized = validate_result(result)
    expected = _revision(expected_revision)
    if normalized["target_revision"] != expected:
        raise StaleRevisionError("The result revision does not match the current target revision.")
    generation = normalized["target_generation"] if expected_generation is None else _strict_int(expected_generation, "expected_generation", 0, MAX_TARGET_GENERATION)
    if normalized["target_generation"] != generation:
        raise StaleRevisionError("The endpoint target generation changed before this result arrived.")

    with _write_transaction(conn, "endpoint_health_apply"):
        previous = _health_row(conn, normalized["vpn_id"])
        if previous and normalized["target_generation"] < int(previous["target_generation"]):
            raise StaleRevisionError("The endpoint target generation is older than stored state.")
        revision_changed = bool(previous and previous["target_revision"] != expected)
        generation_changed = normalized["target_generation"] != (int(previous["target_generation"]) if previous else -1)
        if previous and not revision_changed and normalized["target_generation"] == int(previous["target_generation"]):
            previous_cycle = int(previous["cycle_id"])
            if normalized["cycle_id"] and normalized["cycle_id"] < previous_cycle:
                raise StaleCycleError("The endpoint cycle is older than stored state.")
            if normalized["cycle_id"] == previous_cycle and normalized["cycle_id"] and normalized["lease_id"] == previous["lease_id"]:
                return previous
            if normalized["cycle_id"] == previous_cycle and normalized["cycle_id"] and normalized["lease_id"] != previous["lease_id"]:
                raise StaleCycleError("The endpoint cycle lease does not match stored state.")
            if previous["last_checked_at"] is not None and normalized["checked_at"] < int(previous["last_checked_at"]):
                raise StaleCycleError("The endpoint observation is older than stored state.")

        old_state = str(previous["state"]) if previous else "accessible"
        failures = int(previous["consecutive_failures"] or 0) if previous else 0
        checked_at = normalized["checked_at"]
        success = bool(normalized["icmp_ok"] or normalized["protocol_ok"])
        if success:
            new_state = "accessible"
            failures = 0
            last_success = checked_at
        else:
            failures = min(failures + 1, MAX_CONSECUTIVE_FAILURES)
            new_state = "unreachable" if failures >= FAILURE_THRESHOLD else old_state
            last_success = previous["last_success_at"] if previous else None
        transitioned = previous is not None and new_state != old_state
        last_transition = checked_at if transitioned else (previous["last_transition_at"] if previous else None)
        cycle_id = normalized["cycle_id"] or (int(previous["cycle_id"]) + 1 if previous else 1)
        lease_id = normalized["lease_id"] or (str(previous["lease_id"]) if previous else "legacy")
        if revision_changed or generation_changed:
            failures = 0
            last_success = None
            old_state = "accessible"
            if not success:
                failures = 1
                new_state = "accessible"
            else:
                new_state = "accessible"
            transitioned = False
            last_transition = None

        now = int(time.time())
        conn.execute(
            """INSERT INTO vpn_endpoint_health(
                vpn_id,target_revision,target_generation,cycle_id,lease_id,state,consecutive_failures,
                icmp_ok,protocol_ok,protocol_probe,icmp_code,protocol_code,last_checked_at,last_success_at,
                last_transition_at,updated_at,latency_ms
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(vpn_id) DO UPDATE SET
                target_revision=excluded.target_revision,
                target_generation=excluded.target_generation,
                cycle_id=excluded.cycle_id,
                lease_id=excluded.lease_id,
                state=excluded.state,
                consecutive_failures=excluded.consecutive_failures,
                icmp_ok=excluded.icmp_ok,
                protocol_ok=excluded.protocol_ok,
                protocol_probe=excluded.protocol_probe,
                icmp_code=excluded.icmp_code,
                protocol_code=excluded.protocol_code,
                last_checked_at=excluded.last_checked_at,
                last_success_at=excluded.last_success_at,
                last_transition_at=excluded.last_transition_at,
                updated_at=excluded.updated_at,
                latency_ms=excluded.latency_ms""",
            (
                normalized["vpn_id"], expected, normalized["target_generation"], cycle_id, lease_id,
                new_state, failures, int(normalized["icmp_ok"]), int(normalized["protocol_ok"]),
                normalized["protocol_probe"], normalized["icmp_code"], normalized["protocol_code"],
                checked_at, last_success, last_transition, now, normalized["latency_ms"],
            ),
        )
        if transitioned:
            conn.execute(
                """INSERT INTO vpn_endpoint_health_events(
                    vpn_id,old_state,new_state,icmp_ok,protocol_ok,protocol_probe,icmp_code,protocol_code,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    normalized["vpn_id"], old_state, new_state, int(normalized["icmp_ok"]),
                    int(normalized["protocol_ok"]), normalized["protocol_probe"], normalized["icmp_code"],
                    normalized["protocol_code"], checked_at,
                ),
            )
        _purge_events(conn, checked_at - HISTORY_SECONDS)
        stored = _health_row(conn, normalized["vpn_id"])
        if stored is None:
            raise sqlite3.DatabaseError("Endpoint health row was not stored.")
        return stored


def _unknown_health(vpn_id: int) -> dict[str, Any]:
    return {
        "vpn_id": vpn_id,
        "target_revision": None,
        "target_generation": None,
        "cycle_id": None,
        "lease_id": None,
        "state": "accessible",
        "stored_state": "accessible",
        "has_checked": False,
        "is_stale": False,
        "consecutive_failures": 0,
        "icmp_ok": None,
        "protocol_ok": None,
        "protocol_probe": None,
        "icmp_code": "not_checked",
        "protocol_code": "not_checked",
        "last_checked_at": None,
        "last_success_at": None,
        "last_transition_at": None,
        "updated_at": None,
        "latency_ms": None,
    }


def health_for_vpns(conn: sqlite3.Connection, vpn_ids: Any, *, now: int | None = None) -> dict[int, dict[str, Any]]:
    """Return current state; staleness is metadata, never a third public state."""
    if isinstance(vpn_ids, (str, bytes)):
        raise ValueError("vpn_ids must be an iterable of integers.")
    try:
        values = list(vpn_ids)
    except TypeError as exc:
        raise ValueError("vpn_ids must be an iterable of integers.") from exc
    if len(values) > MAX_HEALTH_QUERY_IDS:
        raise ValueError("Too many VPN IDs requested.")
    ids: list[int] = []
    seen: set[int] = set()
    for value in values:
        vpn_id = _strict_int(value, "vpn_id", 1, MAX_VPN_ID)
        if vpn_id not in seen:
            ids.append(vpn_id)
            seen.add(vpn_id)
    result = {vpn_id: _unknown_health(vpn_id) for vpn_id in ids}
    if not ids:
        return result
    checked_now = int(time.time()) if now is None else _strict_int(now, "now", 0, MAX_TIMESTAMP)
    placeholders = ",".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT {_HEALTH_COLUMN_SQL} FROM vpn_endpoint_health WHERE vpn_id IN ({placeholders})",
        tuple(ids),
    ).fetchall()
    for row in rows:
        item = dict(zip(_HEALTH_COLUMNS, row))
        checked = item["last_checked_at"]
        item["stored_state"] = item["state"]
        item["has_checked"] = checked is not None
        item["is_stale"] = checked is not None and checked_now - int(checked) > STALE_AFTER_SECONDS
        result[item["vpn_id"]] = item
    return result


def public_alert_eligible(health: Mapping[str, Any] | None) -> bool:
    """Return true only after the third complete failure and while evidence is fresh."""
    if not health or health.get("state") != "unreachable":
        return False
    return (
        int(health.get("consecutive_failures") or 0) >= FAILURE_THRESHOLD
        and bool(health.get("has_checked", health.get("last_checked_at") is not None))
        and not bool(health.get("is_stale"))
    )


def history_intervals(
    conn: sqlite3.Connection,
    vpn_id: int,
    *,
    now: int | None = None,
    history_hours: int = HISTORY_HOURS,
) -> list[dict[str, Any]]:
    """Rebuild state intervals from transition events, not per-minute samples."""
    vpn_id = _strict_int(vpn_id, "vpn_id", 1, MAX_VPN_ID)
    history_hours = _strict_int(history_hours, "history_hours", 1, 24 * 30)
    checked_now = int(time.time()) if now is None else _strict_int(now, "now", 0, MAX_TIMESTAMP)
    start = max(0, checked_now - history_hours * 3600)
    events = conn.execute(
        """SELECT old_state,new_state,icmp_ok,protocol_ok,protocol_probe,icmp_code,protocol_code,created_at
           FROM vpn_endpoint_health_events
           WHERE vpn_id=? AND created_at>=? AND created_at<=?
           ORDER BY created_at,id""",
        (vpn_id, start, checked_now),
    ).fetchall()
    health = health_for_vpns(conn, [vpn_id], now=checked_now).get(vpn_id) or _unknown_health(vpn_id)
    state = str(events[0]["old_state"] if events else health.get("state", "accessible"))
    cursor = start
    evidence: dict[str, Any] = {
        "icmp_ok": health.get("icmp_ok"),
        "protocol_ok": health.get("protocol_ok"),
        "protocol_probe": health.get("protocol_probe"),
        "icmp_code": health.get("icmp_code", "not_checked"),
        "protocol_code": health.get("protocol_code", "not_checked"),
    }
    intervals: list[dict[str, Any]] = []
    for event in events:
        at = int(event["created_at"])
        if at > cursor:
            intervals.append({"start_at": cursor, "end_at": at, "state": state, **evidence})
        state = str(event["new_state"])
        evidence = {
            "icmp_ok": bool(event["icmp_ok"]) if event["icmp_ok"] is not None else None,
            "protocol_ok": bool(event["protocol_ok"]) if event["protocol_ok"] is not None else None,
            "protocol_probe": event["protocol_probe"],
            "icmp_code": event["icmp_code"],
            "protocol_code": event["protocol_code"],
        }
        cursor = max(cursor, at)
    if cursor < checked_now:
        intervals.append({"start_at": cursor, "end_at": checked_now, "state": state, **evidence})
    return intervals


# Descriptive aliases used by admin detail views and focused tests.
endpoint_history = history_intervals
reconstruct_history = history_intervals


__all__ = [
    "FAILURE_THRESHOLD",
    "HEALTH_STATES",
    "HISTORY_HOURS",
    "HISTORY_SECONDS",
    "MAX_CONSECUTIVE_FAILURES",
    "MAX_LATENCY_MS",
    "MAX_TIMESTAMP",
    "PROBE_TYPES",
    "RESULT_FIELDS",
    "StaleCycleError",
    "StaleRevisionError",
    "apply_probe_result",
    "configure_sqlite_connection",
    "endpoint_history",
    "ensure_endpoint_health_schema",
    "health_for_vpns",
    "history_intervals",
    "public_alert_eligible",
    "reconstruct_history",
    "target_revision",
    "validate_result",
]
