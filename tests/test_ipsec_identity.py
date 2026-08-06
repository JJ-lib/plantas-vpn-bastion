import os
import importlib.util, tempfile, unittest
from pathlib import Path
SPEC=importlib.util.spec_from_file_location("panelapp",os.environ.get("PANEL_APP_UNDER_TEST","/app/app.py"))
appmod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(appmod)

class IpsecIdentityRegressionTest(unittest.TestCase):
    def test_blank_remote_id_does_not_reuse_public_gateway(self):
        with tempfile.TemporaryDirectory() as td:
            appmod.BASE=td; Path(td,"configs/test").mkdir(parents=True); Path(td,"sites/test").mkdir(parents=True); appmod.dec=lambda value: "secret"
            v={"plant":"Test","slug":"test","host":"198.51.100.10","username":"u","password_enc":"p","psk_enc":"p","ike_version":"ikev1","aggressive":1,"phase1_enc":"aes128","phase1_auth":"sha256","dh_group":"5","phase1_lifetime":"86400","dpd":1,"nat_traversal":1,"phase2_enc":"aes128","phase2_auth":"sha256","phase2_lifetime":"43200","pfs":0,"local_id":"","remote_id":"","modecfg":"pull","remote_subnet":"0.0.0.0/0"}
            appmod.gen_ipsec(v,"test")
            conf=Path(td,"configs/test/ipsec.conf").read_text()
            self.assertIn("rightid=%any",conf)
            self.assertNotIn("rightid=198.51.100.10",conf)

    def test_aggressive_ikev1_allows_blank_remote_id_for_discovery(self):
        f={"vpn_type":"ipsec","plant":"Test","slug":"test","host":"198.51.100.10","username":"u","password":"","psk":"","ike_version":"ikev1","auth_mode":"psk-xauth","exchange_mode":"aggressive","modecfg":"pull","nat_traversal":"1","dpd":"1","phase1_enc":"aes128","phase1_auth":"sha256","dh_group":"5","phase1_lifetime":"86400","phase2_enc":"aes128","phase2_auth":"sha256","phase2_lifetime":"43200","pfs":"0","remote_subnet":"0.0.0.0/0","local_id":"","remote_id":""}
        result=appmod.vpn_vals(f,{"password_enc":"x","psk_enc":"x"},"ipsec")
        self.assertEqual(result["remote_id"],"")

    def test_extracts_and_normalizes_supported_peer_ids(self):
        self.assertEqual(appmod.extract_peer_id("Peer ID is ID_IPV4_ADDR: '203.0.113.254'"),("203.0.113.254","ID_IPV4_ADDR"))
        self.assertEqual(appmod.extract_peer_id("Peer ID is ID_FQDN: 'vpn.example.com'"),("@vpn.example.com","ID_FQDN"))
        self.assertEqual(appmod.extract_peer_id("Peer ID is ID_USER_FQDN: 'gw@example.com'"),("gw@example.com","ID_USER_FQDN"))

    def test_rejects_unsupported_or_unsafe_peer_ids(self):
        self.assertIsNone(appmod.extract_peer_id("Peer ID is ID_KEY_ID: 'opaque'"))
        self.assertIsNone(appmod.extract_peer_id("Peer ID is ID_FQDN: 'bad\nvalue'"))

if __name__=="__main__": unittest.main()
