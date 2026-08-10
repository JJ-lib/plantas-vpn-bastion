import ast
import sqlite3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "panel-app"))

from vpn_endpoint_health import (
    MAX_CONSECUTIVE_FAILURES,
    MAX_LATENCY_MS,
    MAX_TIMESTAMP,
    StaleRevisionError,
    StaleCycleError,
    apply_probe_result,
    ensure_endpoint_health_schema,
    health_for_vpns,
    target_revision,
    validate_result,
)


TABLE_FIELDS = {
    "vpn_id",
    "target_revision",
    "target_generation",
    "cycle_id",
    "lease_id",
    "probe_type",
    "state",
    "public_code",
    "consecutive_failures",
    "first_failure_at",
    "last_checked_at",
    "last_success_at",
    "last_transition_at",
    "latency_ms",
    "last_accepted_at",
    "last_conclusive_at",
}
STATES = {"healthy", "suspect", "down", "unknown", "stale", "disabled"}


class EndpointHealthSchemaTests(unittest.TestCase):
    def conn(self):
        conn = sqlite3.connect(":memory:")
        conn.execute(
            "CREATE TABLE vpns("
            "id INTEGER PRIMARY KEY, active INTEGER NOT NULL, "
            "onboarding_state TEXT NOT NULL)"
        )
        conn.execute("INSERT INTO vpns VALUES(1, 1, 'active')")
        return conn

    @staticmethod
    def insert_health(conn, vpn_id, state="unknown"):
        conn.execute(
            "INSERT INTO vpn_endpoint_health("
            "vpn_id,target_revision,probe_type,state,public_code,"
            "target_generation,cycle_id,lease_id,"
            "consecutive_failures,first_failure_at,last_checked_at,"
            "last_success_at,last_transition_at,latency_ms,last_accepted_at,last_conclusive_at"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                vpn_id,
                "a" * 64,
                "tcp_connect",
                state,
                "not_checked",
                0,
                0,
                "synthetic-lease",
                0,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
        )

    def test_schema_is_idempotent_and_has_only_approved_fields(self):
        conn = self.conn()

        ensure_endpoint_health_schema(conn)
        self.insert_health(conn, 1)
        ensure_endpoint_health_schema(conn)

        fields = {row[1] for row in conn.execute("PRAGMA table_info(vpn_endpoint_health)")}
        self.assertEqual(fields, TABLE_FIELDS)
        self.assertEqual(
            conn.execute("SELECT state FROM vpn_endpoint_health WHERE vpn_id=?", (1,)).fetchone()[0],
            "unknown",
        )

    def test_vpn_id_is_unique_and_states_are_constrained(self):
        conn = self.conn()
        ensure_endpoint_health_schema(conn)

        for vpn_id, state in enumerate(sorted(STATES), start=10):
            self.insert_health(conn, vpn_id, state)
        with self.assertRaises(sqlite3.IntegrityError):
            self.insert_health(conn, 10)
        with self.assertRaises(sqlite3.IntegrityError):
            self.insert_health(conn, 99, "invalid")

    def test_schema_initialization_does_not_mutate_vpn_lifecycle_columns(self):
        conn = self.conn()
        before = conn.execute(
            "SELECT active,onboarding_state FROM vpns WHERE id=?", (1,)
        ).fetchone()

        ensure_endpoint_health_schema(conn)
        ensure_endpoint_health_schema(conn)

        after = conn.execute(
            "SELECT active,onboarding_state FROM vpns WHERE id=?", (1,)
        ).fetchone()
        self.assertEqual(after, before)


TARGET = {
    "vpn_type": "ssl",
    "host": "vpn.example.test",
    "port": 443,
    "transport": "tcp",
    "ike_version": "",
    "aggressive": False,
    "nat_t": False,
}


class EndpointHealthBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            "CREATE TABLE vpns("
            "id INTEGER PRIMARY KEY, active INTEGER NOT NULL, "
            "onboarding_state TEXT NOT NULL)"
        )
        self.conn.execute("INSERT INTO vpns VALUES(1, 1, 'active')")
        ensure_endpoint_health_schema(self.conn)
        self.revision = target_revision(TARGET)
        self.next_cycle = 1

    def result(
        self,
        *,
        revision=None,
        outcome="reachable",
        code="tcp_accept",
        observed_at=1_000,
        latency_ms=25,
        probe_type="tcp_connect",
        target_generation=1,
        cycle_id=1,
        lease_id="synthetic-lease",
    ):
        return {
            "vpn_id": 1,
            "target_revision": revision or self.revision,
            "target_generation": target_generation,
            "cycle_id": cycle_id,
            "lease_id": lease_id,
            "probe_type": probe_type,
            "outcome": outcome,
            "public_code": code,
            "latency_ms": latency_ms,
            "observed_at": observed_at,
        }

    def health(self, *, now=1_000):
        return health_for_vpns(self.conn, [1], now=now)[1]

    def apply(self, **changes):
        expected_revision = changes.pop("expected_revision", self.revision)
        changes.setdefault("cycle_id", self.next_cycle)
        self.next_cycle = max(self.next_cycle, changes["cycle_id"] + 1)
        return apply_probe_result(
            self.conn,
            self.result(**changes),
            expected_revision=expected_revision,
        )

    def test_first_conclusive_failure_becomes_suspect(self):
        self.apply(
            outcome="unreachable",
            code="tcp_unreachable",
            latency_ms=3_000,
        )

        health = self.health()
        self.assertEqual(health["state"], "suspect")
        self.assertEqual(health["consecutive_failures"], 1)
        self.assertEqual(health["first_failure_at"], 1_000)
        self.assertEqual(health["last_checked_at"], 1_000)
        self.assertEqual(health["last_transition_at"], 1_000)
        self.assertIsNone(health["last_success_at"])

    def test_second_failure_becomes_down_and_later_failures_are_capped(self):
        self.apply(outcome="unreachable", code="tcp_unreachable", observed_at=1_000)
        self.apply(outcome="unreachable", code="tcp_unreachable", observed_at=1_300)

        health = self.health(now=1_300)
        self.assertEqual(health["state"], "down")
        self.assertEqual(health["consecutive_failures"], 2)
        self.assertEqual(health["first_failure_at"], 1_000)
        self.assertEqual(health["last_transition_at"], 1_300)

        self.conn.execute(
            "UPDATE vpn_endpoint_health SET consecutive_failures=? WHERE vpn_id=?",
            (MAX_CONSECUTIVE_FAILURES - 1, 1),
        )
        self.apply(outcome="unreachable", code="tcp_unreachable", observed_at=1_600)
        self.apply(outcome="unreachable", code="tcp_unreachable", observed_at=1_900)
        self.assertEqual(
            self.health(now=1_900)["consecutive_failures"],
            MAX_CONSECUTIVE_FAILURES,
        )

    def test_first_success_recovers_to_healthy_and_resets_failures(self):
        self.apply(outcome="unreachable", code="tcp_unreachable", observed_at=1_000)
        self.apply(outcome="unreachable", code="tcp_unreachable", observed_at=1_300)
        self.apply(observed_at=1_600, latency_ms=42)

        health = self.health(now=1_600)
        self.assertEqual(health["state"], "healthy")
        self.assertEqual(health["consecutive_failures"], 0)
        self.assertIsNone(health["first_failure_at"])
        self.assertEqual(health["last_success_at"], 1_600)
        self.assertEqual(health["last_transition_at"], 1_600)
        self.assertEqual(health["latency_ms"], 42)

        self.apply(observed_at=1_900, latency_ms=31)
        self.assertEqual(self.health(now=1_900)["last_transition_at"], 1_600)

    def test_inconclusive_updates_observation_without_changing_conclusive_state(self):
        self.apply(outcome="unreachable", code="tcp_unreachable", observed_at=1_000)
        self.apply(outcome="unreachable", code="tcp_unreachable", observed_at=1_300)
        before = self.health(now=1_300)

        self.apply(
            outcome="inconclusive",
            code="probe_error",
            observed_at=1_600,
            latency_ms=None,
        )

        after = self.health(now=1_600)
        self.assertEqual(after["state"], "down")
        self.assertEqual(
            after["consecutive_failures"], before["consecutive_failures"]
        )
        self.assertEqual(after["first_failure_at"], before["first_failure_at"])
        self.assertEqual(after["last_transition_at"], before["last_transition_at"])
        self.assertEqual(after["public_code"], "probe_error")
        self.assertEqual(after["last_checked_at"], 1_600)

    def test_revision_change_resets_then_applies_current_result(self):
        self.apply(observed_at=1_000)
        new_target = dict(TARGET, host="new-vpn.example.test")
        new_revision = target_revision(new_target)

        apply_probe_result(
            self.conn,
            self.result(
                revision=new_revision,
                outcome="unreachable",
                code="tcp_unreachable",
                observed_at=1_300,
            ),
            expected_revision=new_revision,
        )

        health = self.health(now=1_300)
        self.assertEqual(health["target_revision"], new_revision)
        self.assertEqual(health["state"], "suspect")
        self.assertEqual(health["consecutive_failures"], 1)
        self.assertEqual(health["first_failure_at"], 1_300)
        self.assertIsNone(health["last_success_at"])
        self.assertEqual(health["last_transition_at"], 1_300)

    def test_revision_change_with_inconclusive_result_remains_unknown(self):
        self.apply(observed_at=1_000)
        new_revision = target_revision(dict(TARGET, port=444))

        apply_probe_result(
            self.conn,
            self.result(
                revision=new_revision,
                outcome="inconclusive",
                code="probe_error",
                observed_at=1_300,
                latency_ms=None,
            ),
            expected_revision=new_revision,
        )

        health = self.health(now=1_300)
        self.assertEqual(health["state"], "unknown")
        self.assertEqual(health["consecutive_failures"], 0)
        self.assertIsNone(health["last_success_at"])
        self.assertEqual(health["last_transition_at"], 1_300)

    def test_stale_revision_is_rejected_without_mutation(self):
        self.apply(observed_at=1_000)
        before = tuple(
            self.conn.execute(
                "SELECT * FROM vpn_endpoint_health WHERE vpn_id=?", (1,)
            ).fetchone()
        )
        stale_revision = target_revision(dict(TARGET, port=444))

        with self.assertRaises(StaleRevisionError):
            apply_probe_result(
                self.conn,
                self.result(revision=stale_revision, observed_at=1_300),
                expected_revision=self.revision,
            )

        after = tuple(
            self.conn.execute(
                "SELECT * FROM vpn_endpoint_health WHERE vpn_id=?", (1,)
            ).fetchone()
        )
        self.assertEqual(after, before)

    def test_failed_revision_transition_rolls_back_atomically(self):
        self.apply(observed_at=1_000)
        before = tuple(
            self.conn.execute(
                "SELECT * FROM vpn_endpoint_health WHERE vpn_id=?", (1,)
            ).fetchone()
        )
        new_revision = target_revision(dict(TARGET, port=444))
        self.conn.execute(
            "CREATE TRIGGER reject_synthetic_healthy_update "
            "BEFORE UPDATE ON vpn_endpoint_health "
            "WHEN NEW.state='healthy' "
            "BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END"
        )

        with self.assertRaises(sqlite3.DatabaseError):
            apply_probe_result(
                self.conn,
                self.result(revision=new_revision, observed_at=1_300),
                expected_revision=new_revision,
            )

        after = tuple(
            self.conn.execute(
                "SELECT * FROM vpn_endpoint_health WHERE vpn_id=?", (1,)
            ).fetchone()
        )
        self.assertEqual(after, before)

    def test_apply_never_changes_vpn_lifecycle_columns(self):
        before = self.conn.execute(
            "SELECT active,onboarding_state FROM vpns WHERE id=?", (1,)
        ).fetchone()

        self.apply(outcome="unreachable", code="tcp_unreachable", observed_at=1_000)
        self.apply(outcome="unreachable", code="tcp_unreachable", observed_at=1_300)
        self.apply(observed_at=1_600)

        after = self.conn.execute(
            "SELECT active,onboarding_state FROM vpns WHERE id=?", (1,)
        ).fetchone()
        self.assertEqual(tuple(after), tuple(before))

    def test_older_cycle_is_rejected_atomically_and_duplicate_is_idempotent(self):
        first = self.apply(cycle_id=2, observed_at=1_000)
        duplicate = self.apply(cycle_id=2, observed_at=1_300, latency_ms=99)
        self.assertEqual(duplicate, first)
        self.assertEqual(self.health(now=1_300)["last_checked_at"], 1_000)

        with self.assertRaises(StaleCycleError):
            self.apply(cycle_id=1, outcome="unreachable", code="tcp_unreachable")
        self.assertEqual(self.health(now=1_300)["cycle_id"], 2)

    def test_older_observation_timestamp_is_rejected_even_for_a_newer_cycle(self):
        self.apply(cycle_id=1, observed_at=2_000)
        with self.assertRaises(StaleCycleError):
            self.apply(cycle_id=2, observed_at=1_999)

    def test_new_generation_resets_state_and_acceptance_is_separate_from_conclusive_time(self):
        self.apply(cycle_id=1, outcome="unreachable", code="tcp_unreachable", observed_at=1_000)
        self.apply(cycle_id=2, outcome="inconclusive", code="probe_error", latency_ms=None, observed_at=1_500)
        health = self.health(now=1_500)
        self.assertEqual(health["last_accepted_at"], 1_500)
        self.assertEqual(health["last_conclusive_at"], 1_000)

        result = self.apply(target_generation=2, cycle_id=1, observed_at=2_000)
        self.assertEqual(result["target_generation"], 2)
        self.assertEqual(result["cycle_id"], 1)
        self.assertEqual(self.health(now=2_000)["state"], "healthy")

    def test_lease_id_is_part_of_the_accepted_cycle(self):
        self.apply(lease_id="lease-a")
        with self.assertRaises(ValueError):
            self.apply(lease_id="lease-b", cycle_id=1)


class EndpointHealthValidationTests(unittest.TestCase):
    def valid_result(self):
        return {
            "vpn_id": 1,
            "target_revision": target_revision(TARGET),
            "target_generation": 1,
            "cycle_id": 1,
            "lease_id": "synthetic-lease",
            "probe_type": "tcp_connect",
            "outcome": "reachable",
            "public_code": "tcp_accept",
            "latency_ms": 10,
            "observed_at": 1_000,
        }

    def test_target_revision_is_canonical_and_uses_only_probe_config(self):
        reordered = {key: TARGET[key] for key in reversed(TARGET)}
        with_unrelated_values = dict(
            TARGET,
            plant="Synthetic Plant",
            username="synthetic-user-a",
            password_enc=object(),
            psk_enc=object(),
        )
        changed_unrelated_values = dict(
            with_unrelated_values,
            username="synthetic-user-b",
            password_enc=object(),
            psk_enc=object(),
        )

        revision = target_revision(TARGET)
        self.assertEqual(target_revision(reordered), revision)
        self.assertEqual(target_revision(with_unrelated_values), revision)
        self.assertEqual(target_revision(changed_unrelated_values), revision)
        self.assertNotEqual(target_revision(dict(TARGET, host="other.example.test")), revision)
        self.assertNotEqual(target_revision(dict(TARGET, transport="udp")), revision)

    def test_target_revision_rejects_invalid_probe_configuration(self):
        bad_targets = [
            dict(TARGET, vpn_type="unknown"),
            dict(TARGET, host=""),
            dict(TARGET, port=0),
            dict(TARGET, port=True),
            dict(TARGET, transport="sctp"),
            dict(TARGET, aggressive="yes"),
        ]
        for bad in bad_targets:
            with self.subTest(target=bad):
                with self.assertRaises(ValueError):
                    target_revision(bad)

    def test_validate_result_accepts_only_the_exact_bounded_contract(self):
        valid = self.valid_result()
        self.assertEqual(validate_result(valid), valid)
        inconclusive_ike = dict(valid, probe_type="ike", public_code="ike_no_response", outcome="inconclusive")
        self.assertEqual(validate_result(inconclusive_ike), inconclusive_ike)

        invalid_results = []
        for missing in valid:
            invalid = dict(valid)
            invalid.pop(missing)
            invalid_results.append(invalid)
        invalid_results.extend(
            [
                dict(valid, unexpected="value"),
                dict(valid, vpn_id=True),
                dict(valid, vpn_id=0),
                dict(valid, target_revision="x" * 64),
                dict(valid, probe_type="raw_socket"),
                dict(valid, outcome="timeout"),
                dict(valid, public_code="unknown_code"),
                dict(valid, outcome="unreachable", public_code="tcp_accept"),
                dict(valid, probe_type="ike", public_code="tcp_accept"),
                dict(valid, public_code=""),
                dict(valid, public_code="UPPERCASE"),
                dict(valid, public_code="x" * 65),
                dict(valid, observed_at=True),
                dict(valid, observed_at=-1),
                dict(valid, observed_at=MAX_TIMESTAMP + 1),
                dict(valid, latency_ms=True),
                dict(valid, latency_ms=-1),
                dict(valid, latency_ms=MAX_LATENCY_MS + 1),
            ]
        )
        for invalid in invalid_results:
            with self.subTest(result=invalid):
                with self.assertRaises(ValueError):
                    validate_result(invalid)

    def test_health_query_interprets_only_observations_older_than_15m_as_stale(self):
        conn = sqlite3.connect(":memory:")
        ensure_endpoint_health_schema(conn)
        revision = target_revision(TARGET)
        result = self.valid_result()
        result["observed_at"] = 100
        apply_probe_result(conn, result, expected_revision=revision)

        at_boundary = health_for_vpns(conn, [1, 2], now=1_000)
        stale = health_for_vpns(conn, [1, 2], now=1_001)

        self.assertEqual(at_boundary[1]["state"], "healthy")
        self.assertFalse(at_boundary[1]["is_stale"])
        self.assertEqual(stale[1]["state"], "stale")
        self.assertEqual(stale[1]["stored_state"], "healthy")
        self.assertTrue(stale[1]["is_stale"])
        self.assertEqual(stale[2]["state"], "unknown")
        self.assertFalse(stale[2]["is_stale"])
        stored = conn.execute(
            "SELECT state FROM vpn_endpoint_health WHERE vpn_id=?", (1,)
        ).fetchone()[0]
        self.assertEqual(stored, "healthy")

    def test_disabled_state_is_not_reinterpreted_as_stale(self):
        conn = sqlite3.connect(":memory:")
        ensure_endpoint_health_schema(conn)
        result = self.valid_result()
        apply_probe_result(
            conn,
            result,
            expected_revision=result["target_revision"],
        )
        conn.execute(
            "UPDATE vpn_endpoint_health SET state='disabled',last_checked_at=? WHERE vpn_id=?",
            (100, 1),
        )

        health = health_for_vpns(conn, [1], now=10_000)[1]
        self.assertEqual(health["state"], "disabled")
        self.assertFalse(health["is_stale"])


class EndpointHealthAppIntegrationTests(unittest.TestCase):
    def test_app_init_calls_endpoint_health_schema_initializer(self):
        tree = ast.parse((ROOT / "panel-app" / "app.py").read_text(encoding="utf-8"))
        imported = any(
            isinstance(node, ast.ImportFrom)
            and node.module == "vpn_endpoint_health"
            and any(alias.name == "ensure_endpoint_health_schema" for alias in node.names)
            for node in tree.body
        )
        init_function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "init"
        )
        called_with_connection = any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ensure_endpoint_health_schema"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "c"
            for node in ast.walk(init_function)
        )

        self.assertTrue(imported)
        self.assertTrue(called_with_connection)


if __name__ == "__main__":
    unittest.main()
