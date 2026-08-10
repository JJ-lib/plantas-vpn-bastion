import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import types
import unittest
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


class EndpointMonitorApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.data_dir = Path(cls.tmp.name) / "data"
        cls.data_dir.mkdir()
        cls.db_path = cls.data_dir / "panel.db"
        cls.token_path = cls.data_dir / "monitor-token"
        cls.token = "synthetic-monitor-token-0123456789abcdef-0123456789abcdef"
        cls.token_path.write_text(cls.token + "\n", encoding="ascii")
        os.environ.update(
            {
                "PANEL_DATA_DIR": str(cls.data_dir),
                "PANEL_DB": str(cls.db_path),
                "PROJECT_DIR": str(cls.tmp.name),
                "PANEL_BOOTSTRAP_ADMIN_PASSWORD": "synthetic-test-password-only",
                "PANEL_TEST_ALLOW_MISSING_CSRF": "1",
                "VPN_ENDPOINT_MONITOR_TOKEN_FILE": str(cls.token_path),
                "VPN_ENDPOINT_MONITOR_COLLECTION_ENABLED": "true",
            }
        )
        spec = importlib.util.spec_from_file_location("endpoint_monitor_api_app", PANEL / "app.py")
        cls.mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.mod
        spec.loader.exec_module(cls.mod)
        cls.mod.app.config.update(TESTING=True)
        cls.client = cls.mod.app.test_client()
        with cls.mod.app.app_context():
            conn = cls.mod.db()
            conn.execute(
                """INSERT INTO vpns(
                    plant,slug,host,port,username,password_enc,active,created_at,
                    vpn_type,ike_version,aggressive,nat_traversal,openvpn_profile_enc
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "Synthetic IPsec",
                    "synthetic-ipsec",
                    "vpn.example.test",
                    "500",
                    "sealed-user",
                    "sealed-password",
                    1,
                    "now",
                    "ipsec",
                    "ikev1",
                    1,
                    1,
                    "",
                ),
            )
            cls.ipsec_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.execute(
                """INSERT INTO vpns(
                    plant,slug,host,port,username,password_enc,active,created_at,
                    vpn_type,openvpn_profile_enc,openvpn_requires_auth
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "Synthetic OpenVPN",
                    "synthetic-openvpn",
                    "openvpn.example.test",
                    "443",
                    "sealed-user",
                    "sealed-password",
                    1,
                    "now",
                    "openvpn",
                    cls.mod.enc("client\ndev tun\nproto tcp-client\nremote openvpn.example.test 443\n"),
                    1,
                ),
            )
            cls.openvpn_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.execute(
                """INSERT INTO vpns(
                    plant,slug,host,port,username,password_enc,active,created_at,vpn_type
                ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    "Synthetic Draft",
                    "synthetic-draft",
                    "draft.example.test",
                    "1194",
                    "sealed-user",
                    "sealed-password",
                    0,
                    "now",
                    "openvpn",
                ),
            )
            cls.inactive_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.commit()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def auth_headers(self, token=None):
        return {"Authorization": "Bearer " + (self.token if token is None else token)}

    def target_payload(self):
        response = self.client.get(
            "/internal/vpn-endpoint-monitor/targets", headers=self.auth_headers()
        )
        self.assertEqual(response.status_code, 200)
        return response.get_json()

    def test_missing_and_wrong_tokens_are_indistinguishable_404(self):
        path = "/internal/vpn-endpoint-monitor/targets"
        missing = self.client.get(path)
        wrong = self.client.get(path, headers={"Authorization": "Bearer wrong-token"})
        malformed = self.client.get(path, headers={"Authorization": "Basic anything"})
        self.assertEqual((missing.status_code, wrong.status_code, malformed.status_code), (404, 404, 404))
        self.assertEqual(missing.get_data(), wrong.get_data())

    def test_valid_token_returns_only_safe_active_target_fields(self):
        payload = self.target_payload()
        self.assertEqual(set(payload), {"targets"})
        self.assertEqual(len(payload["targets"]), 2)
        by_id = {item["vpn_id"]: item for item in payload["targets"]}
        self.assertNotIn(self.inactive_id, by_id)
        self.assertEqual(
            set(by_id[self.ipsec_id]),
            {
                "vpn_id",
                "target_revision",
                "target_generation",
                "cycle_id",
                "lease_id",
                "vpn_type",
                "host",
                "port",
                "transport",
                "ike_version",
                "aggressive",
                "nat_t",
            },
        )
        self.assertEqual(by_id[self.ipsec_id]["transport"], "udp")
        self.assertEqual(by_id[self.ipsec_id]["nat_t"], True)
        self.assertEqual(by_id[self.openvpn_id]["transport"], "tcp")
        serialized = json.dumps(payload, sort_keys=True)
        for forbidden in (
            "username",
            "password",
            "password_enc",
            "psk",
            "profile",
            "certificate",
            "sealed-password",
            "synthetic-test-password-only",
        ):
            self.assertNotIn(forbidden, serialized.lower())

    def test_missing_or_unsafe_token_file_fails_closed(self):
        path = self.mod.os.environ["VPN_ENDPOINT_MONITOR_TOKEN_FILE"]
        original = Path(path).read_bytes()
        try:
            Path(path).unlink()
            self.assertEqual(
                self.client.get(
                    "/internal/vpn-endpoint-monitor/targets", headers=self.auth_headers()
                ).status_code,
                404,
            )
            Path(path).mkdir()
            self.assertEqual(
                self.client.get(
                    "/internal/vpn-endpoint-monitor/targets", headers=self.auth_headers()
                ).status_code,
                404,
            )
        finally:
            if Path(path).is_dir():
                Path(path).rmdir()
            Path(path).write_bytes(original)

    def test_valid_auth_uses_constant_time_token_comparison(self):
        original = self.mod.hmac.compare_digest
        calls = []

        def compare(left, right):
            calls.append((type(left), type(right)))
            return original(left, right)

        self.mod.hmac.compare_digest = compare
        try:
            response = self.client.get(
                "/internal/vpn-endpoint-monitor/targets", headers=self.auth_headers()
            )
        finally:
            self.mod.hmac.compare_digest = original
        self.assertEqual(response.status_code, 200)
        self.assertEqual(calls, [(bytes, bytes)])

    def test_oversized_result_body_is_rejected_before_json_processing(self):
        body = b"{" + (b"x" * (70 * 1024))
        response = self.client.post(
            "/internal/vpn-endpoint-monitor/results",
            data=body,
            content_type="application/json",
            headers=self.auth_headers(),
        )
        self.assertEqual(response.status_code, 413)

    def test_valid_result_is_stored_and_stale_revision_is_rejected(self):
        targets = self.target_payload()["targets"]
        target = next(item for item in targets if item["vpn_id"] == self.ipsec_id)
        result = {
            "vpn_id": target["vpn_id"],
            "target_revision": target["target_revision"],
            "target_generation": target["target_generation"],
            "cycle_id": target["cycle_id"],
            "lease_id": target["lease_id"],
            "probe_type": "ike",
            "outcome": "reachable",
            "public_code": "ike_response",
            "latency_ms": 42,
            "observed_at": 1_700_000_000,
        }
        response = self.client.post(
            "/internal/vpn-endpoint-monitor/results",
            json={"results": [result]},
            headers=self.auth_headers(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"accepted": 1, "ok": True, "rejected": 0})
        with self.mod.app.app_context():
            row = self.mod.db().execute(
                "SELECT state,consecutive_failures FROM vpn_endpoint_health WHERE vpn_id=?",
                (self.ipsec_id,),
            ).fetchone()
            self.assertEqual(tuple(row), ("healthy", 0))

        stale = dict(result, target_revision="0" * 64, public_code="ike_no_response", outcome="unreachable")
        response = self.client.post(
            "/internal/vpn-endpoint-monitor/results",
            json={"results": [stale]},
            headers=self.auth_headers(),
        )
        self.assertEqual(response.status_code, 409)
        with self.mod.app.app_context():
            row = self.mod.db().execute(
                "SELECT state,consecutive_failures FROM vpn_endpoint_health WHERE vpn_id=?",
                (self.ipsec_id,),
            ).fetchone()
            self.assertEqual(tuple(row), ("healthy", 0))

    def test_invalid_batch_duplicate_and_unknown_ids_are_rejected_without_mutation(self):
        payload = self.target_payload()["targets"]
        target = payload[0]
        result = {
            "vpn_id": target["vpn_id"],
            "target_revision": target["target_revision"],
            "target_generation": target["target_generation"],
            "cycle_id": target["cycle_id"],
            "lease_id": target["lease_id"],
            "probe_type": "tcp_connect" if target["transport"] == "tcp" else "ike",
            "outcome": "reachable",
            "public_code": "tcp_accept" if target["transport"] == "tcp" else "ike_response",
            "latency_ms": 1,
            "observed_at": 1_700_000_001,
        }
        duplicate = self.client.post(
            "/internal/vpn-endpoint-monitor/results",
            json={"results": [result, result]},
            headers=self.auth_headers(),
        )
        self.assertEqual(duplicate.status_code, 400)
        unknown = self.client.post(
            "/internal/vpn-endpoint-monitor/results",
            json={"results": [dict(result, vpn_id=999999)]},
            headers=self.auth_headers(),
        )
        self.assertEqual(unknown.status_code, 409)


if __name__ == "__main__":
    unittest.main()
