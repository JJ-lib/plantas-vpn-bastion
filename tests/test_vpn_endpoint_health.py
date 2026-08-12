import ast
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "panel-app"))

from vpn_endpoint_health import (  # noqa: E402
    FAILURE_THRESHOLD,
    HISTORY_SECONDS,
    MAX_CONSECUTIVE_FAILURES,
    MAX_LATENCY_MS,
    MAX_TIMESTAMP,
    StaleCycleError,
    StaleRevisionError,
    apply_probe_result,
    configure_sqlite_connection,
    ensure_endpoint_health_schema,
    health_for_vpns,
    history_intervals,
    public_alert_eligible,
    target_revision,
    validate_result,
)


TARGET = {
    "vpn_type": "ssl",
    "host": "vpn.example.test",
    "port": 443,
    "transport": "tcp",
}


class HealthFixture(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        ensure_endpoint_health_schema(self.conn)
        self.revision = target_revision(TARGET)

    def result(self, *, checked_at=1000, icmp_ok=False, protocol_ok=False, **extra):
        result = {
            "vpn_id": 1,
            "target_revision": extra.pop("target_revision", self.revision),
            "icmp_ok": icmp_ok,
            "protocol_ok": protocol_ok,
            "protocol_probe": extra.pop("protocol_probe", "tcp"),
            "checked_at": checked_at,
        }
        result.update(extra)
        return result

    def apply(self, **changes):
        expected = changes.pop("expected_revision", self.revision)
        return apply_probe_result(self.conn, self.result(**changes), expected_revision=expected)

    def health(self, now=1000):
        return health_for_vpns(self.conn, [1], now=now)[1]


class SchemaTests(HealthFixture):
    def test_schema_is_idempotent_and_has_only_public_states(self):
        ensure_endpoint_health_schema(self.conn)
        ensure_endpoint_health_schema(self.conn)
        columns = {row[1] for row in self.conn.execute("PRAGMA table_info(vpn_endpoint_health)")}
        self.assertTrue({
            "vpn_id", "target_revision", "state", "consecutive_failures",
            "icmp_ok", "protocol_ok", "protocol_probe", "last_checked_at",
            "last_success_at", "last_transition_at", "updated_at",
        } <= columns)
        event_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(vpn_endpoint_health_events)")}
        self.assertTrue({
            "id", "vpn_id", "old_state", "new_state", "icmp_ok", "protocol_ok",
            "protocol_probe", "created_at",
        } <= event_columns)
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO vpn_endpoint_health(vpn_id,target_revision,state,consecutive_failures) VALUES(?,?,?,?)",
                (1, self.revision, "suspect", 1),
            )

    def test_schema_does_not_mutate_lifecycle_columns(self):
        self.conn.execute("CREATE TABLE vpns(id INTEGER PRIMARY KEY, active INTEGER, onboarding_state TEXT)")
        self.conn.execute("INSERT INTO vpns VALUES(1,1,'active')")
        before = tuple(self.conn.execute("SELECT active,onboarding_state FROM vpns WHERE id=1").fetchone())
        ensure_endpoint_health_schema(self.conn)
        after = tuple(self.conn.execute("SELECT active,onboarding_state FROM vpns WHERE id=1").fetchone())
        self.assertEqual(after, before)

    def test_sqlite_concurrency_pragmas_are_configured(self):
        configure_sqlite_connection(self.conn)
        self.assertEqual(self.conn.execute("PRAGMA busy_timeout").fetchone()[0], 5000)

    def test_partial_existing_schema_is_migrated_atomically(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(
            """CREATE TABLE vpn_endpoint_health(
                vpn_id INTEGER PRIMARY KEY,
                target_revision TEXT NOT NULL,
                state TEXT NOT NULL,
                consecutive_failures INTEGER NOT NULL,
                icmp_ok INTEGER,
                updated_at INTEGER NOT NULL
            )"""
        )
        conn.execute(
            "INSERT INTO vpn_endpoint_health VALUES(?,?,?,?,?,?)",
            (1, self.revision, "accessible", 2, 0, 1000),
        )
        ensure_endpoint_health_schema(conn)
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(vpn_endpoint_health)")
        }
        self.assertTrue(
            {
                "target_generation", "cycle_id", "lease_id", "protocol_ok",
                "protocol_probe", "icmp_code", "protocol_code", "last_checked_at",
                "last_success_at", "last_transition_at", "latency_ms",
            } <= columns
        )
        self.assertEqual(
            tuple(conn.execute(
                "SELECT state,consecutive_failures FROM vpn_endpoint_health WHERE vpn_id=1"
            ).fetchone()),
            ("accessible", 2),
        )
        conn.close()

    def test_file_backed_wal_concurrent_schema_and_reopen_persist_state(self):
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "panel.db")
            errors = []

            def initialize():
                try:
                    conn = sqlite3.connect(database, timeout=5)
                    conn.row_factory = sqlite3.Row
                    ensure_endpoint_health_schema(conn)
                    conn.close()
                except Exception as error:  # pragma: no cover - asserted below
                    errors.append(error)

            threads = [threading.Thread(target=initialize) for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(errors, [])

            conn = sqlite3.connect(database, timeout=5)
            conn.row_factory = sqlite3.Row
            configure_sqlite_connection(conn)
            self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            revision = target_revision(TARGET)
            for checked_at in (1000, 1060, 1120):
                apply_probe_result(
                    conn,
                    self.result(checked_at=checked_at),
                    expected_revision=revision,
                )
            conn.close()

            reopened = sqlite3.connect(database, timeout=5)
            reopened.row_factory = sqlite3.Row
            configure_sqlite_connection(reopened)
            health = health_for_vpns(reopened, [1], now=1120)[1]
            self.assertEqual(health["state"], "unreachable")
            self.assertEqual(health["consecutive_failures"], FAILURE_THRESHOLD)
            self.assertEqual(
                reopened.execute(
                    "SELECT COUNT(*) FROM vpn_endpoint_health_events"
                ).fetchone()[0],
                1,
            )
            reopened.close()


class StateMachineTests(HealthFixture):
    def test_or_rule_marks_cycle_accessible(self):
        for icmp_ok, protocol_ok in ((True, False), (False, True), (True, True)):
            with self.subTest(icmp_ok=icmp_ok, protocol_ok=protocol_ok):
                self.apply(checked_at=1000, icmp_ok=icmp_ok, protocol_ok=protocol_ok)
                health = self.health()
                self.assertEqual(health["state"], "accessible")
                self.assertEqual(health["consecutive_failures"], 0)
                self.conn.execute("DELETE FROM vpn_endpoint_health")
                self.conn.execute("DELETE FROM vpn_endpoint_health_events")

    def test_three_complete_failures_transition_and_one_success_recovers(self):
        for checked_at in (1000, 1060):
            self.apply(checked_at=checked_at)
            self.assertEqual(self.health(checked_at)["state"], "accessible")
        self.apply(checked_at=1120)
        health = self.health(1120)
        self.assertEqual(health["state"], "unreachable")
        self.assertEqual(health["consecutive_failures"], FAILURE_THRESHOLD)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM vpn_endpoint_health_events").fetchone()[0], 1)
        event = self.conn.execute(
            "SELECT old_state,new_state,icmp_ok,protocol_ok,protocol_probe FROM vpn_endpoint_health_events"
        ).fetchone()
        self.assertEqual(tuple(event), ("accessible", "unreachable", 0, 0, "tcp"))

        self.apply(checked_at=1180, icmp_ok=False, protocol_ok=True)
        health = self.health(1180)
        self.assertEqual(health["state"], "accessible")
        self.assertEqual(health["consecutive_failures"], 0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM vpn_endpoint_health_events").fetchone()[0], 2)

    def test_failures_after_unreachable_are_capped_without_new_events(self):
        for checked_at in (1000, 1060, 1120, 1180):
            self.apply(checked_at=checked_at)
        self.conn.execute(
            "UPDATE vpn_endpoint_health SET consecutive_failures=? WHERE vpn_id=1",
            (MAX_CONSECUTIVE_FAILURES - 1,),
        )
        self.conn.commit()
        self.apply(checked_at=1240)
        self.assertEqual(self.health(1240)["consecutive_failures"], MAX_CONSECUTIVE_FAILURES)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM vpn_endpoint_health_events").fetchone()[0], 1)

    def test_revision_change_resets_counter_and_accepts_current_result(self):
        for checked_at in (1000, 1060):
            self.apply(checked_at=checked_at)
        new_revision = target_revision({**TARGET, "host": "new.example.test"})
        result = self.result(
            target_revision=new_revision,
            target_generation=2,
            cycle_id=1,
            lease_id="new-lease",
            checked_at=500,
        )
        stored = apply_probe_result(self.conn, result, expected_revision=new_revision, expected_generation=2)
        self.assertEqual(stored["target_revision"], new_revision)
        self.assertEqual(stored["state"], "accessible")
        self.assertEqual(stored["consecutive_failures"], 1)
        self.assertEqual(stored["last_checked_at"], 500)

    def test_result_revision_mismatch_is_rejected_without_mutation(self):
        self.apply(checked_at=1000, icmp_ok=True)
        before = tuple(self.conn.execute("SELECT * FROM vpn_endpoint_health WHERE vpn_id=1").fetchone())
        other = target_revision({**TARGET, "port": 444})
        with self.assertRaises(StaleRevisionError):
            apply_probe_result(self.conn, self.result(target_revision=other), expected_revision=self.revision)
        after = tuple(self.conn.execute("SELECT * FROM vpn_endpoint_health WHERE vpn_id=1").fetchone())
        self.assertEqual(after, before)

    def test_cycle_duplicate_is_idempotent_and_older_cycle_is_rejected(self):
        first = self.apply(checked_at=1000, icmp_ok=True, cycle_id=4, lease_id="lease-a")
        duplicate = self.apply(checked_at=1100, icmp_ok=False, cycle_id=4, lease_id="lease-a")
        self.assertEqual(duplicate, first)
        with self.assertRaises(StaleCycleError):
            self.apply(checked_at=1200, cycle_id=3, lease_id="lease-a")

    def test_lifecycle_columns_remain_untouched(self):
        self.conn.execute("CREATE TABLE vpns(id INTEGER PRIMARY KEY, active INTEGER, onboarding_state TEXT)")
        self.conn.execute("INSERT INTO vpns VALUES(1,1,'active')")
        before = tuple(self.conn.execute("SELECT active,onboarding_state FROM vpns WHERE id=1").fetchone())
        for checked_at in (1000, 1060, 1120, 1180):
            self.apply(checked_at=checked_at)
        after = tuple(self.conn.execute("SELECT active,onboarding_state FROM vpns WHERE id=1").fetchone())
        self.assertEqual(after, before)

    def test_database_failure_rolls_back_state_and_event_atomically(self):
        self.apply(checked_at=1000, icmp_ok=True)
        self.apply(checked_at=1060)
        self.apply(checked_at=1120)
        before = tuple(self.conn.execute("SELECT * FROM vpn_endpoint_health WHERE vpn_id=1").fetchone())
        self.conn.execute(
            "CREATE TRIGGER reject_unreachable BEFORE UPDATE ON vpn_endpoint_health "
            "WHEN NEW.state='unreachable' BEGIN SELECT RAISE(ABORT,'synthetic'); END"
        )
        with self.assertRaises(sqlite3.DatabaseError):
            self.apply(checked_at=1180)
        after = tuple(self.conn.execute("SELECT * FROM vpn_endpoint_health WHERE vpn_id=1").fetchone())
        self.assertEqual(after, before)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM vpn_endpoint_health_events").fetchone()[0], 0)


class ValidationAndHistoryTests(HealthFixture):
    def test_validate_result_accepts_canonical_iso_timestamp_only(self):
        result = self.result(icmp_ok=True, checked_at="2026-08-11T10:30:00Z")
        normalized = validate_result(result)
        self.assertIsInstance(normalized["checked_at"], int)
        for legacy in ("probe_type", "outcome", "public_code", "observed_at", "state"):
            with self.subTest(legacy=legacy):
                with self.assertRaises(ValueError):
                    validate_result({**result, legacy: "legacy"})

    def test_validate_result_rejects_invalid_types_and_bounds(self):
        valid = self.result(icmp_ok=True, protocol_ok=False, latency_ms=10)
        invalid = [
            {**valid, "vpn_id": True},
            {**valid, "target_revision": "x" * 64},
            {**valid, "icmp_ok": 1},
            {**valid, "protocol_probe": "tcp_connect"},
            {**valid, "checked_at": MAX_TIMESTAMP + 1},
            {**valid, "latency_ms": MAX_LATENCY_MS + 1},
            {**valid, "unexpected": "value"},
        ]
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_result(value)

    def test_staleness_is_metadata_not_a_third_public_state(self):
        self.apply(checked_at=100)
        current = health_for_vpns(self.conn, [1], now=100 + 15 * 60)[1]
        stale = health_for_vpns(self.conn, [1], now=100 + 15 * 60 + 1)[1]
        self.assertEqual(current["state"], "accessible")
        self.assertEqual(stale["state"], "accessible")
        self.assertTrue(stale["is_stale"])
        self.assertEqual(stale["stored_state"], "accessible")
        self.assertFalse(public_alert_eligible(stale))

    def test_only_transitions_are_stored_and_history_uses_transition_evidence(self):
        self.apply(checked_at=1000, icmp_ok=True)
        for checked_at in (1060, 1120):
            self.apply(checked_at=checked_at, icmp_ok=True)
        for checked_at in (1180, 1240, 1300):
            self.apply(checked_at=checked_at)
        self.apply(checked_at=1360, icmp_ok=True)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM vpn_endpoint_health_events").fetchone()[0], 2)
        intervals = history_intervals(self.conn, 1, now=1360, history_hours=5)
        self.assertEqual({item["state"] for item in intervals}, {"accessible", "unreachable"})
        self.assertTrue(all(item["start_at"] < item["end_at"] for item in intervals))
        self.assertTrue(any(item["state"] == "unreachable" and item["protocol_ok"] is False for item in intervals))

    def test_history_purges_events_older_than_five_hours(self):
        self.conn.execute(
            "INSERT INTO vpn_endpoint_health_events(vpn_id,old_state,new_state,icmp_ok,protocol_ok,protocol_probe,created_at) VALUES(?,?,?,?,?,?,?)",
            (1, "accessible", "unreachable", 0, 0, "tcp", 0),
        )
        self.conn.commit()
        self.apply(checked_at=HISTORY_SECONDS + 100, icmp_ok=True)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM vpn_endpoint_health_events WHERE created_at < ?", (100,)).fetchone()[0],
            0,
        )

    def test_tuple_and_row_legacy_migrations_preserve_timestamp_and_diagnostics(self):
        for row_factory in (None, sqlite3.Row):
            conn = sqlite3.connect(":memory:")
            if row_factory:
                conn.row_factory = row_factory
            conn.execute(
                "CREATE TABLE vpn_endpoint_health(vpn_id INTEGER PRIMARY KEY,target_revision TEXT,probe_type TEXT,state TEXT,public_code TEXT,outcome TEXT,consecutive_failures INTEGER,observed_at INTEGER,latency_ms INTEGER)"
            )
            conn.execute("INSERT INTO vpn_endpoint_health VALUES(1,?,?,?,?,?,?,?,?)", ("a" * 64, "tcp_connect", "down", "tcp_unreachable", "unreachable", 2, 1000, 9))
            ensure_endpoint_health_schema(conn)
            row = conn.execute("SELECT state,protocol_probe,protocol_ok,last_checked_at,protocol_code FROM vpn_endpoint_health WHERE vpn_id=1").fetchone()
            self.assertEqual(tuple(row), ("unreachable", "tcp", 0, 1000, "tcp_unreachable"))
            conn.close()


class AppIntegrationTests(unittest.TestCase):
    def test_app_initializes_endpoint_health_schema(self):
        tree = ast.parse((ROOT / "panel-app" / "app.py").read_text(encoding="utf-8"))
        imported = any(
            isinstance(node, ast.ImportFrom)
            and node.module == "vpn_endpoint_health"
            and any(alias.name == "ensure_endpoint_health_schema" for alias in node.names)
            for node in tree.body
        )
        init_function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "init")
        called = any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ensure_endpoint_health_schema"
            for node in ast.walk(init_function)
        )
        self.assertTrue(imported)
        self.assertTrue(called)


if __name__ == "__main__":
    unittest.main()
