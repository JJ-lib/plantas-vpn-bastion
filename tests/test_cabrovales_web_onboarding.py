import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class CabrovalesWebOnboardingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        os.environ["PANEL_DATA_DIR"] = str(root / "data")
        os.environ["PANEL_DB"] = str(root / "data" / "panel.db")
        os.environ["PROJECT_DIR"] = str(root)
        os.environ["PANEL_BOOTSTRAP_ADMIN_PASSWORD"] = "cabrovales-web-test-password"
        os.environ["BASTION_PUBLIC_ORIGIN"] = "https://192.0.2.1"
        (root / "configs").mkdir(parents=True, exist_ok=True)
        (root / "configs" / "bridge.pem").write_text("test-certificate\n")
        (root / "sites" / "cabrovales").mkdir(parents=True, exist_ok=True)
        (root / "plants" / "cabrovales").mkdir(parents=True, exist_ok=True)
        spec = importlib.util.spec_from_file_location(
            "panel_app_cabrovales_web",
            os.environ["PANEL_APP_UNDER_TEST"],
        )
        cls.app = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.app)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        with self.app.app.app_context():
            conn = self.app.db()
            conn.execute("DELETE FROM equipment")
            conn.execute("DELETE FROM vpns")
            conn.execute(
                "INSERT INTO vpns(plant,slug,active) VALUES(?,?,1)",
                ("CABROVALES", "cabrovales"),
            )
            conn.execute(
                "INSERT INTO vpns(plant,slug,active) VALUES(?,?,1)",
                ("OTHER PLANT", "other-plant"),
            )
            conn.commit()

    def set_profile(self, plant="CABROVALES", profile="minimal_auto", host="local.domain"):
        with self.app.app.app_context():
            self.app.db().execute(
                "UPDATE vpns SET web_onboarding_profile=?, web_default_host=? WHERE plant=?",
                (profile, host, plant),
            )
            self.app.db().commit()

    def add_web(self, **overrides):
        values = {
            "plant": "CABROVALES",
            "name": "TEST WEB",
            "kind": "WEB",
            "real_ip": "192.0.2.10",
            "real_port": "80",
            "public_url": "https://192.168.72.179:19001/",
            "active": 1,
            "created_at": "2026-09-18T00:00:00",
            "proxy_port": 19001,
            "web_mode": "bridge_tls",
            "web_effective_mode": "bridge_tls",
            "web_diagnostic": "",
            "web_proxy_port": None,
            "web_bridge_host": "",
        }
        values.update(overrides)
        with self.app.app.app_context():
            columns = ",".join(values)
            marks = ",".join("?" for _ in values)
            self.app.db().execute(
                f"INSERT INTO equipment({columns}) VALUES({marks})",
                tuple(values.values()),
            )
            self.app.db().commit()

    def test_profile_is_explicit_and_isolated(self):
        with self.app.app.app_context():
            vpn_cols = {row[1] for row in self.app.db().execute("pragma table_info(vpns)")}
            equipment_cols = {row[1] for row in self.app.db().execute("pragma table_info(equipment)")}
        self.assertTrue({"web_onboarding_profile", "web_default_host"} <= vpn_cols)
        self.assertTrue(
            {
                "web_upstream_scheme",
                "web_upstream_host",
                "web_validation_profile",
                "web_validation_state",
            }
            <= equipment_cols
        )
        with self.app.app.app_context():
            self.assertEqual(("legacy", ""), self.app.web_onboarding_profile("OTHER PLANT"))
        self.set_profile()
        with self.app.app.app_context():
            self.assertEqual(("minimal_auto", "local.domain"), self.app.web_onboarding_profile("CABROVALES"))

    def test_bridge_rejects_loopback_public_origin(self):
        self.set_profile()
        with patch.object(self.app, "PUBLIC_ORIGIN", "https://127.0.0.1"):
            with self.assertRaisesRegex(ValueError, "origen público"):
                with self.app.app.app_context():
                    self.app.equipment_values(
                        {
                            "plant": "CABROVALES",
                            "name": "LOOPBACK WEB",
                            "kind": "WEB",
                            "real_ip": "192.0.2.10",
                            "real_port": "443",
                        }
                    )

    def test_minimal_form_is_only_used_for_cabrovales_new_web(self):
        with self.app.app.app_context():
            base = {
                "plant": "CABROVALES",
                "kind": "WEB",
                "name": "TEST WEB",
                "real_ip": "192.0.2.10",
                "real_port": "80",
            }
            minimal = self.app.ef(base, minimal_web_onboarding=True)
            legacy = self.app.ef({**base, "plant": "OTHER PLANT"})
        self.assertIn("name='real_ip'", minimal)
        self.assertIn("name='real_port'", minimal)
        self.assertNotIn("name='web_mode'", minimal)
        self.assertNotIn("name='web_bridge_host'", minimal)
        self.assertNotIn("name='public_port'", minimal)
        self.assertIn("name='web_mode'", legacy)

    def test_probe_classifies_generic_http(self):
        result = self.app.probe_web_equipment_auto(
            "cabrovales",
            "192.0.2.10",
            "80",
            "local.domain",
            runner=self.fake_runner(
                {
                    "http": ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n", "<html><script src='/app.js'></script></html>"),
                    "https": ("", "", 7),
                }
            ),
        )
        self.assertEqual("generic_http", result["profile"])
        self.assertEqual("http", result["upstream_scheme"])
        self.assertEqual("", result["upstream_host"])

    def test_probe_classifies_host_sni_https(self):
        result = self.app.probe_web_equipment_auto(
            "cabrovales",
            "192.0.2.11",
            "443",
            "local.domain",
            runner=self.fake_runner(
                {
                    "http": ("", "", 7),
                    "https": ("HTTP/1.1 404 Not Found\r\n", "", 0),
                    "host_https": ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n", "<html>ok</html>"),
                }
            ),
        )
        self.assertEqual("plant_host_https", result["profile"])
        self.assertEqual("https", result["upstream_scheme"])
        self.assertEqual("local.domain", result["upstream_host"])

    def test_http_backend_gets_public_tls_without_backend_ssl(self):
        self.set_profile()
        self.add_web(real_port="80")
        with self.app.app.app_context():
            self.app.db().execute(
                "UPDATE equipment SET web_upstream_scheme='http', web_upstream_host='', web_validation_profile='generic_http', web_validation_state='validated'"
            )
            self.app.db().commit()
            cfg, _ = self.app.render_haproxy_for_plant("CABROVALES")
        self.assertIn("bind *:19001 ssl crt /etc/haproxy/certs/bridge.pem", cfg)
        self.assertIn("server target 192.0.2.10:80", cfg)
        self.assertNotIn("server target 192.0.2.10:80 ssl", cfg)

    def test_https_backend_gets_tls_without_sni_when_host_is_not_required(self):
        self.set_profile()
        self.add_web(real_port="443", proxy_port=19002, public_url="https://192.168.72.179:19002/")
        with self.app.app.app_context():
            self.app.db().execute(
                "UPDATE equipment SET web_upstream_scheme='https', web_upstream_host='', web_validation_profile='generic_https', web_validation_state='validated'"
            )
            self.app.db().commit()
            cfg, _ = self.app.render_haproxy_for_plant("CABROVALES")
        self.assertIn("server target 192.0.2.10:443 ssl verify none ciphers", cfg)
        self.assertNotIn("sni str(", cfg)

    def test_https_backend_gets_sni_when_host_is_required(self):
        self.set_profile()
        self.add_web(name="SNI WEB", real_port="443", proxy_port=19003, public_url="https://192.168.72.179:19003/")
        with self.app.app.app_context():
            self.app.db().execute(
                "UPDATE equipment SET web_upstream_scheme='https', web_upstream_host='local.domain', web_bridge_host='local.domain', web_validation_profile='plant_host_https', web_validation_state='validated'"
            )
            self.app.db().commit()
            cfg, _ = self.app.render_haproxy_for_plant("CABROVALES")
        self.assertIn("server target 192.0.2.10:443 ssl verify none sni str(local.domain) ciphers", cfg)
        self.assertIn("http-request set-header Host local.domain", cfg)

    def test_unreachable_preflight_is_rejected(self):
        self.set_profile()
        with self.app.app.app_context():
            values = self.app.equipment_values(
                {
                    "plant": "CABROVALES",
                    "name": "UNREACHABLE",
                    "kind": "WEB",
                    "real_ip": "192.0.2.99",
                    "real_port": "80",
                }
            )
            original = self.app.probe_web_equipment_auto
            self.app.probe_web_equipment_auto = lambda *args, **kwargs: {
                "profile": "unreachable",
                "diagnostic": "sin respuesta",
            }
            try:
                with self.assertRaisesRegex(ValueError, "sin respuesta"):
                    self.app.finalize_web_settings(values, 77)
            finally:
                self.app.probe_web_equipment_auto = original
            self.assertEqual(0, self.app.db().execute("select count(*) from equipment").fetchone()[0])

    @staticmethod
    def fake_runner(responses):
        def runner(command, **kwargs):
            command_text = " ".join(command)
            if "--connect-to" in command_text:
                key = "host_https"
            elif "https://" in command_text:
                key = "https"
            else:
                key = "http"
            stdout, body, *returncode = responses.get(key, ("", "", 7))
            class Result:
                pass
            result = Result()
            result.stdout = stdout if "-D" in command else body
            result.stderr = "unreachable" if returncode and returncode[0] else ""
            result.returncode = returncode[0] if returncode else 0
            return result
        return runner


if __name__ == "__main__":
    unittest.main()
