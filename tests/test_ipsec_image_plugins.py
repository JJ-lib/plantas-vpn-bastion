import pathlib
import unittest


class StrongSwanImagePluginTests(unittest.TestCase):
    def test_standard_plugins_are_installed_for_ecp_dh_groups(self):
        dockerfile = pathlib.Path(
            str(pathlib.Path(__file__).resolve().parents[1] / "images/ipsec-proxy/Dockerfile")
        ).read_text(encoding="utf-8")
        self.assertIn(
            "libstrongswan-standard-plugins",
            dockerfile,
            "DH19/20/21 require the strongSwan OpenSSL plugin package",
        )


if __name__ == "__main__":
    unittest.main()
