import os
import importlib.util
import tempfile
import sqlite3
import unittest
from pathlib import Path
from werkzeug.datastructures import MultiDict

SPEC = importlib.util.spec_from_file_location("panelapp_ikev2_multi", os.environ.get("PANEL_APP_UNDER_TEST","/app/app.py"))
appmod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(appmod)


def sample(multiple=True):
    v = {
        "id": 12, "plant": "Example Site 07", "slug": "example-site-07",
        "host": "203.0.113.137", "port": "500", "username": "user",
        "password_enc": "encrypted", "psk_enc": "encrypted", "vpn_type": "ipsec",
        "ipsec_engine": "strongswan", "ike_version": "ikev2",
        "auth_mode": "eap-mschapv2-psk", "aggressive": 0,
        "phase1_enc": "aes256", "phase1_auth": "sha512", "dh_group": "14",
        "phase1_lifetime": "86400", "dpd": 1, "nat_traversal": 1,
        "phase2_enc": "aes256", "phase2_auth": "sha512",
        "phase2_lifetime": "43200", "pfs": 1, "local_id": "",
        "remote_id": "", "modecfg": "pull", "remote_subnet": "0.0.0.0/0",
    }
    if multiple:
        v.update(phase1_enc2="aes256", phase1_auth2="sha256",
                 dh_groups="14,20", phase2_enc2="aes256",
                 phase2_auth2="sha256", pfs_group="20")
    return v


class Ikev2MultipleProposalTests(unittest.TestCase):
    def generate(self, v):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        appmod.BASE = td.name
        Path(td.name, "configs/example-site-07").mkdir(parents=True)
        Path(td.name, "sites/example-site-07").mkdir(parents=True)
        appmod.dec = lambda _: "dummy-secret"
        appmod.gen_ikev2_eap(v, "example-site-07")
        return Path(td.name, "configs/example-site-07/ipsec.conf").read_text()

    def test_generator_preserves_forticlient_proposal_order(self):
        conf = self.generate(sample())
        self.assertIn(
            "ike=aes256-sha512-modp2048,aes256-sha512-ecp384,"
            "aes256-sha256-modp2048,aes256-sha256-ecp384!", conf)
        self.assertIn(
            "esp=aes256-sha512-ecp384,aes256-sha256-ecp384!", conf)

    def test_parser_preserves_repeated_dh_groups_and_second_rows(self):
        f = MultiDict([
            ("vpn_type", "ipsec"), ("plant", "Example Site 07"),
            ("slug", "example-site-07"), ("host", "203.0.113.137"),
            ("username", "user"), ("password", ""), ("psk", ""),
            ("ike_version", "ikev2"), ("ipsec_engine", "strongswan"),
            ("auth_mode", "eap-mschapv2-psk"), ("exchange_mode", "main"),
            ("modecfg", "pull"), ("nat_traversal", "1"), ("dpd", "1"),
            ("phase1_enc", "aes256"), ("phase1_auth", "sha512"),
            ("dh_groups", "14"), ("dh_groups", "20"),
            ("phase1_enc2", "aes256"), ("phase1_auth2", "sha256"),
            ("phase1_lifetime", "86400"), ("phase2_enc", "aes256"),
            ("phase2_auth", "sha512"), ("phase2_enc2", "aes256"),
            ("phase2_auth2", "sha256"), ("phase2_lifetime", "43200"),
            ("pfs", "1"), ("pfs_group", "20"),
            ("remote_subnet", "0.0.0.0/0"), ("local_id", ""),
            ("remote_id", ""),
        ])
        result = appmod.vpn_vals(f, {"password_enc": "x", "psk_enc": "x"}, "ipsec")
        self.assertEqual(result["dh_groups"], "14,20")
        self.assertEqual(result["phase1_enc2"], "aes256")
        self.assertEqual(result["phase1_auth2"], "sha256")
        self.assertEqual(result["phase2_enc2"], "aes256")
        self.assertEqual(result["phase2_auth2"], "sha256")
        self.assertEqual(result["pfs_group"], "20")

    def test_form_exposes_standard_multiple_proposal_fields(self):
        page = appmod.vf(sample(), "ipsec")
        self.assertIn('name="phase1_enc2"', page)
        self.assertIn('name="phase1_auth2"', page)
        self.assertIn('name="dh_groups"', page)
        self.assertIn('name="phase2_enc2"', page)
        self.assertIn('name="phase2_auth2"', page)
        self.assertIn('name="pfs_group"', page)
        self.assertNotIn('Grupo DH principal', page)
        self.assertNotIn('type=hidden name=dh_group', page)
        self.assertIn('data-ikev1-only', page)
        self.assertIn('<select name=dh_group>', page)
        self.assertIn("i.value==='ikev1'", page)

    def test_form_accepts_sqlite_row_from_live_database(self):
        values = sample()
        con = sqlite3.connect(":memory:")
        con.row_factory = sqlite3.Row
        columns = list(values)
        con.execute(
            "create table vpn (" + ",".join(name + " TEXT" for name in columns) + ")"
        )
        con.execute(
            "insert into vpn values (" + ",".join("?" for _ in columns) + ")",
            [values[name] for name in columns],
        )
        row = con.execute("select * from vpn").fetchone()
        page = appmod.vf(row, "ipsec")
        self.assertIn('name="dh_groups"', page)

    def test_legacy_single_proposal_remains_unchanged(self):
        conf = self.generate(sample(multiple=False))
        self.assertIn("ike=aes256-sha512-modp2048!", conf)
        self.assertIn("esp=aes256-sha512-modp2048!", conf)


if __name__ == "__main__":
    unittest.main()
