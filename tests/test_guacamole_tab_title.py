import importlib.util
import os
import re
import unittest
from pathlib import Path

APP = os.environ.get("PANEL_APP_UNDER_TEST", "/app/app.py")
PROJECT_ROOT = Path(os.environ.get("PROJECT_DIR", Path(__file__).resolve().parents[1]))
GUAC_DIR = Path(os.environ.get("GUAC_TITLE_SOURCE_UNDER_TEST", PROJECT_ROOT / "guacamole-json-context-fix"))
spec = importlib.util.spec_from_file_location("panel_app_title_test", APP)
panel_app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(panel_app)


class GuacamoleTabTitleTests(unittest.TestCase):
    def test_plant_names_are_normalized_for_browser_tabs(self):
        self.assertTrue(hasattr(panel_app, "guacamole_tab_title"), "falta guacamole_tab_title")
        cases = [
            ({"id": 1, "plant": "Example Site 03", "name": "SCADA"}, "EXAMPLESITE03"),
            ({"id": 2, "plant": "Example Site 01", "name": "SCADA"}, "EXAMPLESITE01"),
            ({"id": 3, "plant": "Example Site 04", "name": "SCADA"}, "EXAMPLESITE04"),
            ({"id": 4, "plant": "Example Site North", "name": "SCADA"}, "EXAMPLESITENORTH"),
            ({"id": 5, "plant": "***", "name": ""}, "RDP5"),
        ]
        for equipment, expected in cases:
            with self.subTest(equipment=equipment):
                value = panel_app.guacamole_tab_title(equipment)
                self.assertEqual(value, expected)
                self.assertRegex(value, r"^[A-Z0-9]{1,64}$")
        self.assertEqual(len(panel_app.guacamole_tab_title({"id": 6, "plant": "a" * 100})), 64)
        self.assertEqual(len(panel_app.guacamole_tab_title({"id": "9" * 70})), 64)

    def test_launch_url_keeps_ascii_connection_id_and_places_title_before_hash(self):
        url = panel_app.guacamole_client_url("rdp-42", "opaque-token", "EXAMPLESITE03")
        self.assertTrue(url.startswith("/guacamole/?tabTitle=EXAMPLESITE03#/client/"), url)
        self.assertIn("?data=opaque-token", url)
        self.assertNotIn("tabTitle", url.split("#", 1)[1])
        self.assertEqual(panel_app.guacamole_connection_name({"id": 42, "kind": "RDP"}), "rdp-42")
        with self.assertRaises(ValueError):
            panel_app.guacamole_client_url("rdp-42", "opaque-token", "BAD TITLE")

    def test_frontend_applies_only_per_tab_safe_titles(self):
        js = (GUAC_DIR / "tab-title.js").read_text()
        dockerfile = (GUAC_DIR / "Dockerfile").read_text()
        self.assertIn("searchParams.get", js)
        self.assertIn("tabTitle", js)
        self.assertIn("MutationObserver", js)
        self.assertIn("currentClientId", js)
        self.assertIn("stored.clientId", js)
        self.assertIn("hashchange", js)
        self.assertIn("observer.disconnect", js)
        self.assertIn("document.title", js)
        self.assertIn("^[A-Z0-9]{1,64}$", js)
        self.assertNotIn("localStorage", js)
        self.assertIn("sessionStorage", js)
        self.assertIn("history.replaceState", js)
        self.assertIn("searchParams.delete", js)
        self.assertNotIn("innerHTML", js)
        self.assertIn("tab-title.js", dockerfile)
        self.assertIn("rdp-title-1.0.0", dockerfile)


if __name__ == "__main__":
    unittest.main()
