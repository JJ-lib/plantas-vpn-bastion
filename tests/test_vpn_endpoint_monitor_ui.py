import importlib.util
import os
import sys
import tempfile
import types
import unittest
from unittest import mock
from pathlib import Path

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


class EndpointMonitorUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        data_dir = Path(cls.tmp.name) / "data"
        data_dir.mkdir()
        os.environ.update(
            {
                "PANEL_DATA_DIR": str(data_dir),
                "PANEL_DB": str(data_dir / "panel.db"),
                "PROJECT_DIR": cls.tmp.name,
                "PANEL_BOOTSTRAP_ADMIN_PASSWORD": "synthetic-ui-password-only",
                "PANEL_TEST_ALLOW_MISSING_CSRF": "1",
                "VPN_ENDPOINT_PUBLIC_ALERTS_ENABLED": "true",
                "VPN_ENDPOINT_MONITOR_COLLECTION_ENABLED": "true",
                "VPN_ENDPOINT_ADMIN_DIAGNOSTICS_ENABLED": "true",
            }
        )
        spec = importlib.util.spec_from_file_location("endpoint_monitor_ui_app", PANEL / "app.py")
        cls.mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.mod
        spec.loader.exec_module(cls.mod)
        cls.mod.app.config.update(TESTING=True)
        cls.client = cls.mod.app.test_client()
        with cls.mod.app.app_context():
            conn = cls.mod.db()
            conn.execute(
                "INSERT INTO users(username,password_hash,role,active,created_at) VALUES(?,?,?,?,?)",
                ("viewer", "synthetic-hash", "user", 1, "now"),
            )
            cls.viewer_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.execute(
                """INSERT INTO vpns(
                    plant,slug,host,port,username,password_enc,active,created_at,
                    vpn_type,ike_version,aggressive,nat_traversal,onboarding_state
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "Synthetic Plant",
                    "synthetic-plant",
                    "vpn.example.test",
                    "500",
                    "sealed-user",
                    "sealed-password",
                    1,
                    "now",
                    "ipsec",
                    "ikev1",
                    0,
                    1,
                    "active",
                ),
            )
            cls.vpn_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            cur = conn.execute(
                """INSERT INTO equipment(
                    plant,name,kind,real_ip,real_port,path,public_url,description,active,created_at,vpn_id
                ) VALUES(?,?,?,?,?,?,?,?,1,?,?)""",
                (
                    "Synthetic Plant",
                    "Synthetic WEB",
                    "WEB",
                    "198.51.100.10",
                    "443",
                    "/",
                    "https://equipment.example.test/",
                    "Synthetic equipment",
                    "now",
                    cls.vpn_id,
                ),
            )
            cls.equipment_id = cur.lastrowid
            conn.execute(
                "INSERT INTO permissions(user_id,equipment_id) VALUES(?,?)",
                (cls.viewer_id, cls.equipment_id),
            )
            conn.commit()
        cls.original_runtime = cls.mod.vpn_runtime

    @classmethod
    def tearDownClass(cls):
        cls.mod.vpn_runtime = cls.original_runtime
        cls.tmp.cleanup()

    def setUp(self):
        with self.mod.app.app_context():
            self.mod.db().execute("DELETE FROM vpn_endpoint_health")
            self.mod.db().commit()
        self.mod.vpn_runtime = lambda _vpn: (False, "", "synthetic tunnel offline")
        self._cycle = 0

    def login_as(self, user_id):
        with self.client.session_transaction() as session:
            session["uid"] = user_id

    def target(self):
        with self.mod.app.app_context():
            row = self.mod.db().execute(
                "SELECT * FROM vpns WHERE id=?", (self.vpn_id,)
            ).fetchone()
            return self.mod._monitor_target_from_row(row)

    def apply_result(self, outcome, code, latency=42, count=1):
        base = self.target()
        now = int(self.mod.time.time())
        with self.mod.app.app_context():
            for _ in range(count):
                self._cycle += 1
                target = dict(base, cycle_id=self._cycle, lease_id=f"test-lease-{self._cycle}")
                result = {
                    "vpn_id": self.vpn_id,
                    "target_revision": target["target_revision"],
                    "target_generation": target["target_generation"],
                    "cycle_id": target["cycle_id"],
                    "lease_id": target["lease_id"],
                    "probe_type": "ike",
                    "outcome": outcome,
                    "public_code": code,
                    "latency_ms": latency,
                    "observed_at": now,
                }
                self.mod.apply_probe_result(
                    self.mod.db(), result, expected_revision=target["target_revision"]
                )

    def test_two_failures_show_user_alert_without_gateway_details(self):
        self.apply_result("unreachable", "ike_no_response", count=2)
        self.login_as(self.viewer_id)
        response = self.client.get("/")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("El servidor público de la VPN no responde", body)
        self.assertIn("role='status'", body)
        self.assertNotIn("vpn.example.test", body)
        self.assertNotIn("vpn.example.test:500", body)
        self.assertNotIn("ike_no_response", body)

    def test_first_failure_does_not_show_user_alert(self):
        self.apply_result("unreachable", "ike_no_response")
        self.login_as(self.viewer_id)
        body = self.client.get("/").get_data(as_text=True)
        self.assertNotIn("El servidor público de la VPN no responde", body)

    def test_online_tunnel_suppresses_alert_but_admin_sees_discrepancy(self):
        self.apply_result("unreachable", "ike_no_response", count=2)
        self.mod.vpn_runtime = lambda _vpn: (True, "198.51.100.20", "")
        self.login_as(1)
        body = self.client.get("/").get_data(as_text=True)
        self.assertNotIn("El servidor público de la VPN no responde", body)
        self.assertIn("La sonda pública no responde, pero el túnel está activo", body)

    def test_success_clears_the_user_alert(self):
        self.apply_result("unreachable", "ike_no_response", count=2)
        self.apply_result("reachable", "ike_response")
        self.login_as(self.viewer_id)
        body = self.client.get("/").get_data(as_text=True)
        self.assertNotIn("El servidor público de la VPN no responde", body)

    def test_admin_table_exposes_only_normalized_diagnostic_fields(self):
        self.apply_result("unreachable", "ike_no_response", latency=None, count=2)
        self.login_as(1)
        response = self.client.get("/admin/vpns")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Endpoint público", body)
        self.assertIn("data-endpoint-state='down'", body)
        self.assertIn("Sin respuesta IKE", body)
        self.assertIn("vpn.example.test:500", body)
        self.assertNotIn("sealed-password", body)
        self.assertNotIn("synthetic tunnel offline", body)

    def test_unauthorized_user_cannot_view_admin_diagnostics(self):
        self.login_as(self.viewer_id)
        self.assertEqual(self.client.get("/admin/vpns").status_code, 403)

    def test_collection_and_admin_diagnostics_flags_fail_closed_independently(self):
        with self.mod.app.app_context():
            target = self.mod._monitor_target_from_row(
                self.mod.db().execute("SELECT * FROM vpns WHERE id=?", (self.vpn_id,)).fetchone()
            )
        with self.mod.app.test_request_context():
            with mock.patch.dict(
                os.environ,
                {
                    "VPN_ENDPOINT_MONITOR_COLLECTION_ENABLED": "false",
                    "VPN_ENDPOINT_ADMIN_DIAGNOSTICS_ENABLED": "true",
                },
                clear=False,
            ):
                self.assertFalse(self.mod.endpoint_monitor_collection_enabled())
                self.assertEqual(
                    self.client.get("/internal/vpn-endpoint-monitor/targets").status_code,
                    404,
                )
        with mock.patch.dict(
            os.environ,
            {
                "VPN_ENDPOINT_MONITOR_COLLECTION_ENABLED": "true",
                "VPN_ENDPOINT_ADMIN_DIAGNOSTICS_ENABLED": "false",
            },
            clear=False,
        ):
            self.assertTrue(self.mod.endpoint_monitor_collection_enabled())
            self.assertFalse(self.mod.endpoint_admin_diagnostics_enabled())
            self.login_as(1)
            body = self.client.get("/admin/vpns").get_data(as_text=True)
            self.assertNotIn("Sin respuesta IKE", body)
            self.assertNotIn("data-endpoint-state", body)

    def test_missing_gate_values_are_fail_closed_and_public_alert_default_is_false(self):
        with mock.patch.dict(
            os.environ,
            {},
            clear=True,
        ):
            self.assertFalse(self.mod.endpoint_monitor_collection_enabled())
            self.assertFalse(self.mod.endpoint_admin_diagnostics_enabled())
            self.assertFalse(self.mod.endpoint_public_alerts_enabled())


if __name__ == "__main__":
    unittest.main()
