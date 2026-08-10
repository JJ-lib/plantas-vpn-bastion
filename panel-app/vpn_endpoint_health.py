"""Persistence and state transitions for public VPN endpoint health.

The monitor reports only normalized observations.  This module validates that
contract, owns the atomic health state machine, and keeps endpoint evidence
separate from VPN activation and onboarding state.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from contextlib import contextmanager
from typing import Any


HEALTH_STATES = frozenset(
    {"healthy", "suspect", "down", "unknown", "stale", "disabled"}
)
PROBE_TYPES = frozenset({"tcp_connect", "ike", "openvpn_udp"})
OUTCOMES = frozenset({"reachable", "unreachable", "inconclusive"})
VPN_TYPES = frozenset({"ssl", "ipsec", "pptp", "openvpn"})
TRANSPORTS = frozenset({"tcp", "udp"})
IKE_VERSIONS = frozenset({"ikev1", "ikev2"})

MAX_CONSECUTIVE_FAILURES = 255
MAX_LATENCY_MS = 60_000
MAX_TIMESTAMP = 253_402_300_799  # 9999-12-31T23:59:59Z
MAX_VPN_ID = 2**63 - 1
MAX_HEALTH_QUERY_IDS = 500
STALE_AFTER_SECONDS = 15 * 60

_RESULT_FIELDS = frozenset(
    {
        "vpn_id",
        "target_revision",
        "probe_type",
        "outcome",
        "public_code",
        "latency_ms",
        "observed_at",
    }
)
_REVISION_RE = re.compile(r"[0-9a-f]{64}\Z")
_PUBLIC_CODE_RE = re.compile(r"[a-z0-9_]{1,64}\Z")
_PUBLIC_CODE_RULES = {
    "tcp_accept": ("reachable", frozenset({"tcp_connect"})),
    "tcp_unreachable": ("unreachable", frozenset({"tcp_connect"})),
    "ike_response": ("reachable", frozenset({"ike"})),
    "ike_no_response": ("unreachable", frozenset({"ike"})),
    "openvpn_udp_response": ("reachable", frozenset({"openvpn_udp"})),
    "udp_port_unreachable": ("unreachable", frozenset({"openvpn_udp"})),
    "udp_silent": ("inconclusive", frozenset({"openvpn_udp"})),
    "dns_failed": ("inconclusive", PROBE_TYPES),
    "dns_failure": ("inconclusive", PROBE_TYPES),
    "dns_timeout": ("inconclusive", PROBE_TYPES),
    "dns_no_answers": ("inconclusive", PROBE_TYPES),
    "dns_no_global_address": ("inconclusive", PROBE_TYPES),
    "private_or_reserved_destination": ("inconclusive", PROBE_TYPES),
    "probe_error": ("inconclusive", PROBE_TYPES),
    "unsupported_probe": ("inconclusive", PROBE_TYPES),
}

_HEALTH_COLUMNS = (
    "vpn_id",
    "target_revision",
    "probe_type",
    "state",
    "public_code",
    "consecutive_failures",
    "first_failure_at",
    "last_checked_at",
    "last_success_at",
    "last_transition_at",
    "latency_ms",
)
_HEALTH_COLUMN_SQL = ",".join(_HEALTH_COLUMNS)

_SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS vpn_endpoint_health(
    vpn_id INTEGER PRIMARY KEY CHECK(vpn_id BETWEEN 1 AND {MAX_VPN_ID}),
    target_revision TEXT NOT NULL CHECK(length(target_revision) = 64),
    probe_type TEXT NOT NULL CHECK(probe_type IN ('tcp_connect','ike','openvpn_udp')),
    state TEXT NOT NULL CHECK(state IN ('healthy','suspect','down','unknown','stale','disabled')),
    public_code TEXT NOT NULL CHECK(length(public_code) BETWEEN 1 AND 64),
    consecutive_failures INTEGER NOT NULL DEFAULT 0
        CHECK(consecutive_failures BETWEEN 0 AND {MAX_CONSECUTIVE_FAILURES}),
    first_failure_at INTEGER
        CHECK(first_failure_at IS NULL OR first_failure_at BETWEEN 0 AND {MAX_TIMESTAMP}),
    last_checked_at INTEGER
        CHECK(last_checked_at IS NULL OR last_checked_at BETWEEN 0 AND {MAX_TIMESTAMP}),
    last_success_at INTEGER
        CHECK(last_success_at IS NULL OR last_success_at BETWEEN 0 AND {MAX_TIMESTAMP}),
    last_transition_at INTEGER
        CHECK(last_transition_at IS NULL OR last_transition_at BETWEEN 0 AND {MAX_TIMESTAMP}),
    latency_ms INTEGER
        CHECK(latency_ms IS NULL OR latency_ms BETWEEN 0 AND {MAX_LATENCY_MS})
)
"""


class StaleRevisionError(ValueError):
    """The worker result does not describe the panel's current target."""


def _mapping_keys(value: Any) -> set[str]:
    if not hasattr(value, "keys") or not callable(value.keys):
        raise ValueError("Expected a mapping.")
    try:
        return set(value.keys())
    except (TypeError, ValueError) as exc:
        raise ValueError("Expected a mapping.") from exc


def _required_value(mapping: Any, key: str) -> Any:
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


def _config_bool(value: Any, label: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool) and value in (0, 1):
        return bool(value)
    raise ValueError(f"{label} must be boolean.")


def _config_port(value: Any) -> int:
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


def _bounded_enum(value: Any, label: str, accepted: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in accepted:
        raise ValueError(f"Invalid {label}.")
    return value


def _validated_revision(value: Any) -> str:
    if not isinstance(value, str) or not _REVISION_RE.fullmatch(value):
        raise ValueError("Invalid target revision.")
    return value


def target_revision(config: Any) -> str:
    """Hash only canonical, non-secret fields that can change a probe."""

    keys = _mapping_keys(config)
    required = {"vpn_type", "host", "port", "transport"}
    if not required <= keys:
        missing = ", ".join(sorted(required - keys))
        raise ValueError(f"Missing probe configuration: {missing}.")

    vpn_type_raw = _required_value(config, "vpn_type")
    if not isinstance(vpn_type_raw, str):
        raise ValueError("Invalid vpn_type.")
    vpn_type = _bounded_enum(vpn_type_raw.strip().lower(), "vpn_type", VPN_TYPES)

    host_raw = _required_value(config, "host")
    if not isinstance(host_raw, str):
        raise ValueError("Invalid host.")
    host = host_raw.strip().lower().rstrip(".")
    if (
        not 1 <= len(host) <= 253
        or any(ord(character) < 33 or ord(character) == 127 for character in host)
    ):
        raise ValueError("Invalid host.")

    transport_raw = _required_value(config, "transport")
    if not isinstance(transport_raw, str):
        raise ValueError("Invalid transport.")
    transport = _bounded_enum(
        transport_raw.strip().lower(), "transport", TRANSPORTS
    )

    canonical = {
        "vpn_type": vpn_type,
        "host": host,
        "port": _config_port(_required_value(config, "port")),
        "transport": transport,
        "ike_version": "",
        "aggressive": False,
        "nat_t": False,
    }
    if vpn_type == "ipsec":
        ike_raw = config["ike_version"] if "ike_version" in keys else "ikev1"
        if not isinstance(ike_raw, str):
            raise ValueError("Invalid ike_version.")
        ike_version = _bounded_enum(
            ike_raw.strip().lower(), "ike_version", IKE_VERSIONS
        )
        aggressive_raw = config["aggressive"] if "aggressive" in keys else False
        nat_key = "nat_t" if "nat_t" in keys else "nat_traversal"
        nat_raw = config[nat_key] if nat_key in keys else False
        canonical.update(
            ike_version=ike_version,
            aggressive=(
                _config_bool(aggressive_raw, "aggressive")
                if ike_version == "ikev1"
                else False
            ),
            nat_t=_config_bool(nat_raw, "nat_t"),
        )
    elif "aggressive" in keys:
        # Reject malformed supplied values even when the field is not applicable,
        # while keeping it out of the non-IPsec revision.
        _config_bool(config["aggressive"], "aggressive")

    payload = json.dumps(
        canonical, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def validate_result(result: Any) -> dict[str, Any]:
    """Validate and copy one exact normalized worker result."""

    keys = _mapping_keys(result)
    if keys != _RESULT_FIELDS:
        raise ValueError("Result fields do not match the endpoint-health contract.")

    vpn_id = _strict_int(
        _required_value(result, "vpn_id"), "vpn_id", 1, MAX_VPN_ID
    )
    revision = _validated_revision(_required_value(result, "target_revision"))
    probe_type = _bounded_enum(
        _required_value(result, "probe_type"), "probe_type", PROBE_TYPES
    )
    outcome = _bounded_enum(
        _required_value(result, "outcome"), "outcome", OUTCOMES
    )

    public_code = _required_value(result, "public_code")
    if not isinstance(public_code, str) or not _PUBLIC_CODE_RE.fullmatch(public_code):
        raise ValueError("Invalid public_code.")
    code_rule = _PUBLIC_CODE_RULES.get(public_code)
    if (
        code_rule is None
        or outcome != code_rule[0]
        or probe_type not in code_rule[1]
    ):
        raise ValueError("public_code does not match the probe outcome.")

    observed_at = _strict_int(
        _required_value(result, "observed_at"),
        "observed_at",
        0,
        MAX_TIMESTAMP,
    )
    latency = _required_value(result, "latency_ms")
    if latency is not None:
        latency = _strict_int(latency, "latency_ms", 0, MAX_LATENCY_MS)

    return {
        "vpn_id": vpn_id,
        "target_revision": revision,
        "probe_type": probe_type,
        "outcome": outcome,
        "public_code": public_code,
        "latency_ms": latency,
        "observed_at": observed_at,
    }


@contextmanager
def _write_transaction(conn: sqlite3.Connection, savepoint: str):
    outer_transaction = conn.in_transaction
    conn.execute(f"SAVEPOINT {savepoint}" if outer_transaction else "BEGIN IMMEDIATE")
    try:
        yield
    except Exception:
        if outer_transaction:
            conn.execute(f"ROLLBACK TO {savepoint}")
            conn.execute(f"RELEASE {savepoint}")
        else:
            conn.rollback()
        raise
    else:
        if outer_transaction:
            conn.execute(f"RELEASE {savepoint}")
        else:
            conn.commit()


def ensure_endpoint_health_schema(conn: sqlite3.Connection) -> None:
    """Create the endpoint-health table without changing VPN lifecycle data."""

    conn.execute("PRAGMA busy_timeout=5000")
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.DatabaseError:
        # An in-memory DB and an already-open transaction may not change modes.
        pass

    with _write_transaction(conn, "endpoint_health_schema"):
        conn.execute(_SCHEMA_SQL)


def _health_row(conn: sqlite3.Connection, vpn_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        f"SELECT {_HEALTH_COLUMN_SQL} FROM vpn_endpoint_health WHERE vpn_id=?",
        (vpn_id,),
    ).fetchone()
    return dict(zip(_HEALTH_COLUMNS, row)) if row is not None else None


def apply_probe_result(
    conn: sqlite3.Connection,
    result: Any,
    *,
    expected_revision: str,
) -> dict[str, Any]:
    """Atomically compare revision, apply one observation, and return stored state."""

    normalized = validate_result(result)
    expected = _validated_revision(expected_revision)

    with _write_transaction(conn, "endpoint_health_apply"):
        if normalized["target_revision"] != expected:
            raise StaleRevisionError("The endpoint target changed before this result arrived.")

        previous = _health_row(conn, normalized["vpn_id"])
        revision_changed = previous is None or previous["target_revision"] != expected
        observed_at = normalized["observed_at"]

        if revision_changed:
            old_state = "unknown"
            failures = 0
            first_failure_at = None
            last_success_at = None
            last_transition_at = observed_at
        else:
            old_state = previous["state"]
            failures = previous["consecutive_failures"]
            first_failure_at = previous["first_failure_at"]
            last_success_at = previous["last_success_at"]
            last_transition_at = previous["last_transition_at"]

        if normalized["outcome"] == "reachable":
            state = "healthy"
            failures = 0
            first_failure_at = None
            last_success_at = observed_at
        elif normalized["outcome"] == "unreachable":
            if failures == 0:
                first_failure_at = observed_at
            failures = min(failures + 1, MAX_CONSECUTIVE_FAILURES)
            state = "suspect" if failures == 1 else "down"
        else:
            state = old_state

        if not revision_changed and state != old_state:
            last_transition_at = observed_at

        values = (
            normalized["vpn_id"],
            expected,
            normalized["probe_type"],
            state,
            normalized["public_code"],
            failures,
            first_failure_at,
            observed_at,
            last_success_at,
            last_transition_at,
            normalized["latency_ms"],
        )
        conn.execute(
            "INSERT INTO vpn_endpoint_health("
            f"{_HEALTH_COLUMN_SQL}) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(vpn_id) DO UPDATE SET "
            "target_revision=excluded.target_revision,"
            "probe_type=excluded.probe_type,"
            "state=excluded.state,"
            "public_code=excluded.public_code,"
            "consecutive_failures=excluded.consecutive_failures,"
            "first_failure_at=excluded.first_failure_at,"
            "last_checked_at=excluded.last_checked_at,"
            "last_success_at=excluded.last_success_at,"
            "last_transition_at=excluded.last_transition_at,"
            "latency_ms=excluded.latency_ms",
            values,
        )
        stored = _health_row(conn, normalized["vpn_id"])
        if stored is None:  # Defensive: the upsert above must create one row.
            raise sqlite3.DatabaseError("Endpoint health row was not stored.")
        return stored


def _unknown_health(vpn_id: int) -> dict[str, Any]:
    return {
        "vpn_id": vpn_id,
        "target_revision": None,
        "probe_type": None,
        "state": "unknown",
        "public_code": "not_checked",
        "consecutive_failures": 0,
        "first_failure_at": None,
        "last_checked_at": None,
        "last_success_at": None,
        "last_transition_at": None,
        "latency_ms": None,
        "stored_state": "unknown",
        "is_stale": False,
    }


def health_for_vpns(
    conn: sqlite3.Connection, vpn_ids: Any, *, now: int | None = None
) -> dict[int, dict[str, Any]]:
    """Return health by VPN ID, overlaying stale as an admin interpretation."""

    if isinstance(vpn_ids, (str, bytes)):
        raise ValueError("vpn_ids must be an iterable of integers.")
    try:
        supplied_ids = list(vpn_ids)
    except TypeError as exc:
        raise ValueError("vpn_ids must be an iterable of integers.") from exc
    if len(supplied_ids) > MAX_HEALTH_QUERY_IDS:
        raise ValueError("Too many VPN IDs requested.")

    ids: list[int] = []
    seen: set[int] = set()
    for value in supplied_ids:
        vpn_id = _strict_int(value, "vpn_id", 1, MAX_VPN_ID)
        if vpn_id not in seen:
            ids.append(vpn_id)
            seen.add(vpn_id)
    if not ids:
        return {}

    checked_now = int(time.time()) if now is None else _strict_int(
        now, "now", 0, MAX_TIMESTAMP
    )
    health = {vpn_id: _unknown_health(vpn_id) for vpn_id in ids}
    placeholders = ",".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT {_HEALTH_COLUMN_SQL} FROM vpn_endpoint_health "
        f"WHERE vpn_id IN ({placeholders})",
        tuple(ids),
    ).fetchall()
    for row in rows:
        item = dict(zip(_HEALTH_COLUMNS, row))
        stored_state = item["state"]
        last_checked_at = item["last_checked_at"]
        is_stale = (
            stored_state != "disabled"
            and last_checked_at is not None
            and checked_now - last_checked_at > STALE_AFTER_SECONDS
        )
        item["stored_state"] = stored_state
        item["is_stale"] = is_stale
        if is_stale:
            item["state"] = "stale"
        health[item["vpn_id"]] = item
    return health
