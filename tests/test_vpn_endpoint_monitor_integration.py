import re
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PATH = ROOT / "docker-compose.yml"
CADDY_PATH = ROOT / "caddy" / "Caddyfile"
ENV_PATH = ROOT / ".env.example"


class ComposeCaddyEnvironmentIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compose_text = COMPOSE_PATH.read_text(encoding="utf-8")
        cls.compose = yaml.safe_load(cls.compose_text)
        cls.services = cls.compose["services"]
        cls.monitor = cls.services["vpn-endpoint-monitor"]
        cls.panel = cls.services["panel"]
        cls.caddy_text = CADDY_PATH.read_text(encoding="utf-8")
        cls.env_text = ENV_PATH.read_text(encoding="utf-8")

    def test_monitor_uses_immutable_image_and_sixty_second_interval(self):
        self.assertEqual(
            self.monitor["image"],
            "${MONITOR_IMAGE:?Set MONITOR_IMAGE to an immutable image reference}",
        )
        command = self.monitor["command"]
        self.assertEqual(command, ["--interval", "60"])
        self.assertNotIn("300", command)
        self.assertEqual(self.monitor["healthcheck"]["test"], ["CMD", "python", "-u", "vpn_endpoint_monitor.py", "--healthcheck"])

    def test_monitor_has_no_database_docker_project_or_host_access(self):
        serialized = repr(self.monitor).lower()
        self.assertNotIn("docker.sock", serialized)
        self.assertNotIn("panel_data", serialized)
        self.assertNotIn("bastion_project_root", serialized)
        self.assertNotIn("project_dir", serialized)
        self.assertNotIn("panel_db", serialized)
        self.assertNotEqual(self.monitor.get("network_mode"), "host")
        self.assertNotIn("ports", self.monitor)
        self.assertNotIn("privileged", self.monitor)

    def test_monitor_filesystem_and_linux_privileges_are_bounded(self):
        self.assertIs(self.monitor["read_only"], True)
        user = str(self.monitor["user"])
        self.assertRegex(user, r"^(?:[1-9][0-9]*)(?::[1-9][0-9]*)?$")
        self.assertEqual(self.monitor["cap_drop"], ["ALL"])
        self.assertEqual(self.monitor["cap_add"], ["NET_RAW"])
        self.assertIn("no-new-privileges:true", self.monitor["security_opt"])

        tmpfs = self.monitor["tmpfs"]
        self.assertTrue(tmpfs)
        self.assertLessEqual(len(tmpfs), 2)
        self.assertTrue(any(re.search(r"(?:^|:)size=\d+[kmg]?(?:,|$)", item, re.I) for item in tmpfs))
        for item in tmpfs:
            self.assertNotIn("size=0", item.lower())

    def test_panel_and_monitor_share_external_read_only_token_secret(self):
        self.assertIn("monitor_token", self.compose["secrets"])
        secret = self.compose["secrets"]["monitor_token"]
        self.assertEqual(
            secret["file"],
            "${VPN_ENDPOINT_MONITOR_TOKEN_FILE:?Set VPN_ENDPOINT_MONITOR_TOKEN_FILE outside Git}",
        )

        panel_secret = next(item for item in self.panel["secrets"] if isinstance(item, dict))
        monitor_secret = next(item for item in self.monitor["secrets"] if isinstance(item, dict))
        self.assertEqual(panel_secret["source"], "monitor_token")
        self.assertEqual(monitor_secret["source"], "monitor_token")
        self.assertEqual(panel_secret["target"], monitor_secret["target"])
        self.assertEqual(panel_secret["mode"], "0440")
        self.assertEqual(monitor_secret["mode"], "0440")
        self.assertEqual(self.panel["environment"]["VPN_ENDPOINT_MONITOR_TOKEN_FILE"], "/run/secrets/monitor-token")
        self.assertEqual(self.monitor["environment"]["VPN_ENDPOINT_MONITOR_TOKEN_FILE"], "/run/secrets/monitor-token")

    def test_panel_retains_existing_database_and_docker_access_while_monitor_has_none(self):
        panel_serialized = repr(self.panel).lower()
        self.assertIn("docker.sock", panel_serialized)
        self.assertIn("panel_data", panel_serialized)
        monitor_serialized = repr(self.monitor).lower()
        self.assertNotIn("docker.sock", monitor_serialized)
        self.assertNotIn("panel_data", monitor_serialized)
        self.assertNotIn("panel.db", monitor_serialized)

    def test_caddy_denies_internal_paths_before_panel_catch_all(self):
        deny = re.search(r"(?ms)^\s*handle\s+/internal(?:\s+/internal/\*)?\s*\{.*?\n\s*\}", self.caddy_text)
        self.assertIsNotNone(deny)
        deny_end = deny.end()
        panel_proxy = self.caddy_text.index("reverse_proxy panel:5000")
        self.assertLess(deny_end, panel_proxy)
        self.assertNotIn("reverse_proxy panel:5000", deny.group(0))
        self.assertRegex(deny.group(0), r"respond\s+[^\n]*\s+4(?:0[034]|29)")

    def test_environment_contract_documents_external_monitor_inputs(self):
        self.assertRegex(self.env_text, r"(?m)^MONITOR_IMAGE=replace-with-immutable-monitor-image\s*$")
        self.assertRegex(self.env_text, r"(?m)^VPN_ENDPOINT_MONITOR_TOKEN_FILE=replace-with-external-token-file\s*$")
        self.assertRegex(self.env_text, r"(?m)^VPN_ENDPOINT_MONITOR_TARGET_IDS=.*$")
        self.assertRegex(self.env_text, r"(?m)^VPN_ENDPOINT_MONITOR_COLLECTION_ENABLED=false\s*$")
        self.assertRegex(self.env_text, r"(?m)^VPN_ENDPOINT_ADMIN_DIAGNOSTICS_ENABLED=false\s*$")
        self.assertRegex(self.env_text, r"(?m)^VPN_ENDPOINT_PUBLIC_ALERTS_ENABLED=false\s*$")
        self.assertNotIn("monitor-token-value", self.env_text)

    def test_compose_passes_independent_fail_closed_gates_and_selector(self):
        self.assertEqual(
            self.panel["environment"]["VPN_ENDPOINT_MONITOR_COLLECTION_ENABLED"],
            "${VPN_ENDPOINT_MONITOR_COLLECTION_ENABLED:-false}",
        )
        self.assertEqual(
            self.panel["environment"]["VPN_ENDPOINT_ADMIN_DIAGNOSTICS_ENABLED"],
            "${VPN_ENDPOINT_ADMIN_DIAGNOSTICS_ENABLED:-false}",
        )
        self.assertEqual(
            self.panel["environment"]["VPN_ENDPOINT_PUBLIC_ALERTS_ENABLED"],
            "${VPN_ENDPOINT_PUBLIC_ALERTS_ENABLED:-false}",
        )
        self.assertEqual(
            self.monitor["environment"]["VPN_ENDPOINT_MONITOR_TARGET_IDS"],
            "${VPN_ENDPOINT_MONITOR_TARGET_IDS}",
        )


if __name__ == "__main__":
    unittest.main()
