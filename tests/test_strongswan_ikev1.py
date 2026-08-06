import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("panelapp_strongswan_ikev1", os.environ.get("PANEL_APP_UNDER_TEST","/app/app.py"))
appmod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(appmod)


def sample(engine="strongswan", ike="ikev1"):
    return {
        "plant":"Test", "slug":"test", "host":"198.51.100.10", "port":"500",
        "username":"user", "password_enc":"encrypted", "psk_enc":"encrypted",
        "vpn_type":"ipsec", "ipsec_engine":engine, "ike_version":ike,
        "auth_mode":"psk-xauth", "aggressive":1, "phase1_enc":"aes128",
        "phase1_auth":"sha1", "dh_group":"5", "phase1_lifetime":"86400",
        "dpd":1, "nat_traversal":1, "phase2_enc":"aes128",
        "phase2_auth":"sha1", "phase2_lifetime":"43200", "pfs":1,
        "local_id":"", "remote_id":"192.0.2.2", "modecfg":"pull",
        "remote_subnet":"0.0.0.0/0",
    }


class StrongSwanIkev1XauthTest(unittest.TestCase):
    def generate(self, v):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        appmod.BASE = td.name
        Path(td.name, "configs/test").mkdir(parents=True)
        Path(td.name, "sites/test").mkdir(parents=True)
        appmod.dec = lambda _: "dummy-secret"
        appmod.gen_ipsec(v, "test")
        return Path(td.name)

    def test_generates_strongswan_ikev1_xauth_modeconfig(self):
        root = self.generate(sample())
        conf = (root / "configs/test/ipsec.conf").read_text()
        self.assertIn("keyexchange=ikev1", conf)
        self.assertIn("aggressive=yes", conf)
        self.assertIn("authby=xauthpsk", conf)
        self.assertIn("xauth=client", conf)
        self.assertIn("leftsourceip=%config", conf)
        self.assertIn("modeconfig=pull", conf)
        self.assertIn("rightid=192.0.2.2", conf)
        self.assertIn("ike=aes128-sha1-modp1536!", conf)
        self.assertIn("esp=aes128-sha1-modp1536!", conf)
        self.assertIn("forceencaps=yes", conf)

    def test_compose_uses_strongswan_image_and_secret_is_private(self):
        root = self.generate(sample())
        compose = (root / "sites/test/compose.yml").read_text()
        self.assertNotIn("build:", compose)
        self.assertIn("image: sha256:4485a68977905a75386d770aa1f473d316b5b2ae808caf03e7df09034ec8e6c6", compose)
        self.assertNotIn("libreswan-proxy", compose)
        mode = os.stat(root / "configs/test/ipsec.secrets").st_mode & 0o777
        self.assertEqual(mode, 0o600)
        self.assertNotIn("dummy-secret", compose)

    def test_libreswan_remains_default_for_existing_ikev1(self):
        v = sample(engine=None)
        v.pop("ipsec_engine")
        root = self.generate(v)
        compose = (root / "sites/test/compose.yml").read_text()
        self.assertNotIn("build:", compose)
        self.assertIn("image: sha256:675e02e42aa3202468ccffbac3096d52eeea542def73c9699085a345c2444155", compose)

    def test_form_accepts_known_engine_and_rejects_unknown(self):
        f = {
            "vpn_type":"ipsec", "plant":"Test", "slug":"test", "host":"198.51.100.10",
            "username":"user", "password":"", "psk":"", "ike_version":"ikev1",
            "ipsec_engine":"strongswan", "auth_mode":"psk-xauth",
            "exchange_mode":"aggressive", "modecfg":"pull", "nat_traversal":"1",
            "dpd":"1", "phase1_enc":"aes128", "phase1_auth":"sha1", "dh_group":"5",
            "phase1_lifetime":"86400", "phase2_enc":"aes128", "phase2_auth":"sha1",
            "phase2_lifetime":"43200", "pfs":"1", "remote_subnet":"0.0.0.0/0",
            "local_id":"", "remote_id":"192.0.2.2",
        }
        result = appmod.vpn_vals(f, {"password_enc":"x", "psk_enc":"x"}, "ipsec")
        self.assertEqual(result["ipsec_engine"], "strongswan")
        f["ipsec_engine"] = "unsafe"
        with self.assertRaises(ValueError):
            appmod.vpn_vals(f, {"password_enc":"x", "psk_enc":"x"}, "ipsec")

if __name__ == "__main__":
    unittest.main()
