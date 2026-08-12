import importlib.util
import os
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

try:
    import fcntl  # type: ignore[import-not-found]
except ModuleNotFoundError:
    fcntl = types.ModuleType("fcntl")
    fcntl.LOCK_EX = 1
    fcntl.LOCK_NB = 2
    fcntl.LOCK_UN = 8
    fcntl.flock = lambda *_args: None
    sys.modules["fcntl"] = fcntl

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel-app"
sys.path.insert(0, str(PANEL))

from vpn_endpoint_health import (  # noqa: E402
    apply_probe_result,
    ensure_endpoint_health_schema,
    health_for_vpns,
    history_intervals,
    target_revision,
    validate_result,
)
import vpn_endpoint_monitor as monitor  # noqa: E402


class FinalHealthContractTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        ensure_endpoint_health_schema(self.conn)
        self.target = {
            "vpn_type": "ssl",
            "host": "vpn.example.test",
            "port": 443,
            "transport": "tcp",
        }
        self.revision = target_revision(self.target)

    def result(self, *, icmp_ok=False, protocol_ok=False, checked_at=1000, probe="tcp", **extra):
        value = {
            "vpn_id": 1,
            "target_revision": self.revision,
            "icmp_ok": icmp_ok,
            "protocol_ok": protocol_ok,
            "protocol_probe": probe,
            "checked_at": checked_at,
        }
        value.update(extra)
        return value

    def test_ike_scan_package_pin_is_documented_and_fixed(self):
        dockerfile = (ROOT / "images" / "vpn-endpoint-monitor" / "Dockerfile").read_text(encoding="utf-8")
        configuration = (ROOT / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8")
        self.assertIn("ike-scan=1.9.5-2", dockerfile)
        self.assertIn("ike-scan 1.9.6", configuration)
        self.assertIn("Debian Bookworm package `ike-scan=1.9.5-2`", configuration)

    def test_schema_exposes_only_two_public_states_and_transition_events(self):
        columns = {row[1] for row in self.conn.execute("PRAGMA table_info(vpn_endpoint_health)")}
        event_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(vpn_endpoint_health_events)")}
        self.assertTrue({
            "vpn_id", "target_revision", "state", "consecutive_failures",
            "icmp_ok", "protocol_ok", "protocol_probe", "last_checked_at",
            "last_success_at", "last_transition_at", "updated_at",
        } <= columns)
        self.assertTrue({
            "id", "vpn_id", "old_state", "new_state", "icmp_ok",
            "protocol_ok", "protocol_probe", "created_at",
        } <= event_columns)
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO vpn_endpoint_health(vpn_id,target_revision,state,consecutive_failures) VALUES(?,?,?,?)",
                (1, self.revision, "suspect", 1),
            )

    def test_icmp_or_protocol_success_and_three_failures_recover(self):
        apply_probe_result(self.conn, self.result(icmp_ok=True, protocol_ok=False, checked_at=1000), expected_revision=self.revision)
        health = health_for_vpns(self.conn, [1], now=1000)[1]
        self.assertEqual(health["state"], "accessible")
        self.assertEqual(health["consecutive_failures"], 0)

        for checked_at in (1060, 1120, 1180):
            apply_probe_result(
                self.conn,
                self.result(checked_at=checked_at),
                expected_revision=self.revision,
            )
        health = health_for_vpns(self.conn, [1], now=1180)[1]
        self.assertEqual(health["state"], "unreachable")
        self.assertEqual(health["consecutive_failures"], 3)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM vpn_endpoint_health_events").fetchone()[0],
            1,
        )

        apply_probe_result(
            self.conn,
            self.result(icmp_ok=False, protocol_ok=True, checked_at=1240),
            expected_revision=self.revision,
        )
        health = health_for_vpns(self.conn, [1], now=1240)[1]
        self.assertEqual(health["state"], "accessible")
        self.assertEqual(health["consecutive_failures"], 0)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM vpn_endpoint_health_events").fetchone()[0],
            2,
        )

    def test_history_purges_old_events_and_reconstructs_intervals(self):
        for checked_at in (1000, 1060, 1120, 1180):
            apply_probe_result(
                self.conn,
                self.result(icmp_ok=checked_at == 1000, checked_at=checked_at),
                expected_revision=self.revision,
            )
        intervals = history_intervals(self.conn, 1, now=1300, history_hours=5)
        self.assertTrue(intervals)
        self.assertEqual({item["state"] for item in intervals}, {"accessible", "unreachable"})

        self.conn.execute(
            "INSERT INTO vpn_endpoint_health_events(vpn_id,old_state,new_state,icmp_ok,protocol_ok,protocol_probe,created_at) VALUES(?,?,?,?,?,?,?)",
            (1, "accessible", "unreachable", 0, 0, "tcp", 0),
        )
        self.conn.commit()
        apply_probe_result(
            self.conn,
            self.result(icmp_ok=True, checked_at=1300),
            expected_revision=self.revision,
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM vpn_endpoint_health_events WHERE created_at < ?",
                (1300 - 5 * 3600,),
            ).fetchone()[0],
            0,
        )

    def test_result_contract_accepts_iso_checked_at_and_rejects_public_legacy_states(self):
        result = self.result(icmp_ok=True, checked_at="2026-08-11T10:30:00Z")
        normalized = validate_result(result)
        self.assertIsInstance(normalized["checked_at"], int)
        with self.assertRaises(ValueError):
            validate_result(dict(result, state="suspect"))


class FinalMonitorProbeTests(unittest.TestCase):
    def target(self, **changes):
        target = {
            "vpn_id": 1,
            "target_revision": "a" * 64,
            "vpn_type": "ssl",
            "host": "vpn.example.test",
            "port": 443,
            "transport": "tcp",
        }
        target.update(changes)
        return target

    def test_cycle_runs_two_icmp_attempts_and_protocol_and_uses_or_rule(self):
        calls = []

        def ping(argv, **kwargs):
            calls.append((argv, kwargs))
            return types.SimpleNamespace(returncode=1)

        def connect(address, timeout):
            self.assertEqual(address, ("8.8.8.8", 443))
            return types.SimpleNamespace(close=lambda: None)

        result = monitor.probe_target(
            self.target(),
            resolver=lambda *_args: ["8.8.8.8"],
            icmp_runner=ping,
            tcp_connector=connect,
        )
        self.assertEqual(len(calls), 2)
        self.assertFalse(result["icmp_ok"])
        self.assertTrue(result["protocol_ok"])
        self.assertTrue(result["icmp_ok"] or result["protocol_ok"])
        self.assertEqual(result["protocol_probe"], "tcp")

    def test_udp_silence_is_protocol_failure_but_icmp_success_keeps_cycle_accessible(self):
        class SilentSocket:
            def settimeout(self, _value): pass
            def connect(self, _address): pass
            def send(self, _payload): return 1
            def recv(self, _size): raise TimeoutError()
            def close(self): pass

        result = monitor.probe_target(
            self.target(vpn_type="openvpn", transport="udp", port=1194),
            resolver=lambda *_args: ["8.8.8.8"],
            icmp_runner=lambda *_args, **_kwargs: types.SimpleNamespace(returncode=0),
            udp_socket_factory=lambda *_args: SilentSocket(),
        )
        self.assertTrue(result["icmp_ok"])
        self.assertFalse(result["protocol_ok"])
        self.assertTrue(result["icmp_ok"] or result["protocol_ok"])
        self.assertEqual(result["protocol_probe"], "openvpn_udp")


class FinalConfigurationTests(unittest.TestCase):
    def test_official_defaults_and_icapability_contract(self):
        self.assertEqual(monitor.DEFAULT_INTERVAL_SECONDS, 60.0)
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn('"--interval", "60"', compose)
        self.assertIn("NET_RAW", compose)
        self.assertIn("VPN_ENDPOINT_MONITOR_INTERVAL=60", (ROOT / ".env.example").read_text(encoding="utf-8"))
        self.assertIn("iputils-ping", (ROOT / "images/vpn-endpoint-monitor/Dockerfile").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
