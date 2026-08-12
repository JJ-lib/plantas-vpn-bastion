import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "images" / "vpn-endpoint-monitor" / "Dockerfile"
RUNBOOK = ROOT / "docs" / "operations" / "vpn-endpoint-monitor-rollout.md"
README = ROOT / "README.md"
IKE_SCAN_VERSION = "1.9.5-2"


class EndpointMonitorOperationsContractTests(unittest.TestCase):
    def setUp(self):
        self.dockerfile = DOCKERFILE.read_text(encoding="utf-8")
        self.runbook = RUNBOOK.read_text(encoding="utf-8")

    def test_ike_scan_package_version_is_exact_and_documented(self):
        pins = re.findall(r"(?m)^\s*ike-scan=([^\\\s]+)", self.dockerfile)
        self.assertEqual(pins, [IKE_SCAN_VERSION])
        self.assertIn(f"`ike-scan={IKE_SCAN_VERSION}`", self.runbook)
        self.assertIn("ike-scan --version", self.runbook)

    def test_token_generation_and_rotation_are_external_atomic_and_non_disclosing(self):
        self.assertIn("umask 077", self.runbook)
        self.assertRegex(self.runbook, r"openssl rand -hex 32 > \"\$TOKEN_TMP\"")
        self.assertIn('chmod 0600 "$TOKEN_TMP"', self.runbook)
        self.assertIn('mv -f "$TOKEN_TMP" "$TOKEN_FILE"', self.runbook)
        self.assertIn("Nunca imprimir", self.runbook)
        self.assertNotRegex(
            self.runbook, r"(?m)^\s*(?:export\s+)?VPN_ENDPOINT_MONITOR_TOKEN="
        )

    def test_rollout_order_is_panel_caddy_token_canary_scheduler_then_ui(self):
        markers = [
            "1. **Panel y migración**",
            "2. **Caddy**",
            "3. **Token**",
            "4. **Canary**",
            "5. **Scheduler**",
            "6. **UI**",
        ]
        positions = [self.runbook.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions))

    def test_rollback_is_bounded_and_preserves_sqlite_and_vpn_runtime(self):
        rollback = self.runbook.split("## Rollback acotado", 1)[1].lower()
        self.assertIn("detener el scheduler", rollback)
        self.assertIn("desactivar la ui", rollback)
        self.assertIn("conservar sqlite", rollback)
        self.assertIn("no reiniciar ni recrear contenedores vpn", rollback)
        self.assertIn("no restaurar una copia completa", rollback)

    def test_readme_links_the_operational_runbook(self):
        readme = README.read_text(encoding="utf-8")
        self.assertIn("docs/operations/vpn-endpoint-monitor-rollout.md", readme)


if __name__ == "__main__":
    unittest.main()
