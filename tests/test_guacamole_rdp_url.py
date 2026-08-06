import os
import base64
import importlib.util
import unittest
from urllib.parse import quote

spec = importlib.util.spec_from_file_location("panel_app", os.environ.get("PANEL_APP_UNDER_TEST", os.environ.get("PANEL_APP_UNDER_TEST","/app/app.py")))
panel_app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(panel_app)

class GuacamoleLaunchUrlTests(unittest.TestCase):
    def test_direct_session_url_uses_official_json_data_without_fake_token(self):
        name = "RDP 203.0.113.14"
        client_id = base64.urlsafe_b64encode((name + "\0c\0json").encode()).decode().rstrip("=")
        expected = "/guacamole/#/client/" + quote(client_id, safe="") + "?data=opaque-token"
        self.assertEqual(panel_app.guacamole_client_url(name, "opaque-token"), expected)
        self.assertNotIn("force-json-auth", expected)

if __name__ == "__main__":
    unittest.main()
