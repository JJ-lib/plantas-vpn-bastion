import os
import hashlib
import importlib.util, unittest
spec=importlib.util.spec_from_file_location("panelapp",os.environ.get("PANEL_APP_UNDER_TEST",os.environ.get("PANEL_APP_UNDER_TEST","/app/app.py")))
appmod=importlib.util.module_from_spec(spec); spec.loader.exec_module(appmod)

class EquipmentTypeTest(unittest.TestCase):
    def test_only_web_rdp_and_vnc_are_accepted(self):
        f={"plant":"Example Site 03","name":"Legacy","kind":"SSH","real_ip":"203.0.113.10","real_port":"22","path":"","public_url":"","public_port":"8099","description":""}
        with self.assertRaisesRegex(ValueError,"WEB, RDP o VNC"):
            appmod.equipment_values(f)

    def test_rdp_defaults_to_3389_and_encrypts_credentials(self):
        appmod.next_public_port=lambda: 8099
        f={"plant":"Example Site 03","name":"PC SCADA","kind":"RDP","real_ip":"203.0.113.20","real_port":"","path":"/ignored","public_url":"","public_port":"","description":"","rdp_username":"DOMAIN\\operator","rdp_password":"synthetic-test-password","rdp_domain":"DOMAIN"}
        try: result=appmod.equipment_values(f)
        except ValueError as exc: self.fail("RDP debe usar 3389 por defecto: "+str(exc))
        self.assertEqual(result["real_port"],"3389")
        self.assertEqual(result["proxy_port"],8099)
        self.assertEqual(result["path"],"")
        self.assertEqual(result["public_url"],"")
        self.assertEqual(appmod.dec(result["rdp_username_enc"]),"DOMAIN\\operator")
        self.assertEqual(appmod.dec(result["rdp_password_enc"]),"synthetic-test-password")

    def test_guacamole_token_contains_expiring_rdp_connection(self):
        import base64, hashlib, hmac, json
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7
        self.assertTrue(hasattr(appmod,"guacamole_token"),"falta generar token Guacamole")
        appmod.GUAC_JSON_KEY = hashlib.sha256(b"synthetic-guac-json-key").hexdigest()[:32]
        e={"id":21,"plant":"Example Site 03","name":"PC SCADA","proxy_port":8099,"rdp_username_enc":appmod.enc("operator"),"rdp_password_enc":appmod.enc("synthetic-test-password"),"rdp_domain_enc":appmod.enc("DOMAIN")}
        token=appmod.guacamole_token("portal-user",[(e,"example-site-03")],now_ms=1000000)
        raw=Cipher(algorithms.AES(bytes.fromhex(appmod.GUAC_JSON_KEY)),modes.CBC(bytes(16))).decryptor().update(base64.b64decode(token))
        unpad=PKCS7(128).unpadder(); clear=unpad.update(raw)+unpad.finalize(); signature,payload=clear[:32],clear[32:]
        self.assertTrue(hmac.compare_digest(signature,hmac.new(bytes.fromhex(appmod.GUAC_JSON_KEY),payload,hashlib.sha256).digest()))
        data=json.loads(payload); conn=data["connections"][appmod.guacamole_connection_name(e)]
        self.assertEqual(data["expires"],1060000)
        self.assertEqual(conn["protocol"],"rdp")
        self.assertEqual(conn["parameters"]["hostname"],"vpn-example-site-03")
        self.assertEqual(conn["parameters"]["port"],"8099")
        self.assertEqual(conn["parameters"]["username"],"operator")
        self.assertEqual(conn["parameters"]["password"],"synthetic-test-password")

    def test_guacamole_connection_identifiers_are_ascii_and_stable(self):
        e={"id":42,"plant":"Planta — Unicode","name":"Equipo ñ"}
        identifier=appmod.guacamole_connection_name(e)
        self.assertEqual("rdp-42",identifier)
        identifier.encode("ascii")

    def test_guacamole_token_contains_all_authorized_rdp_connections(self):
        import base64, json
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7
        appmod.GUAC_JSON_KEY = hashlib.sha256(b"synthetic-guac-json-key").hexdigest()[:32]
        base={"proxy_port":8099,"rdp_username_enc":"","rdp_password_enc":"","rdp_domain_enc":"","rdp_remote_app":""}
        e1={**base,"id":41,"plant":"Example Site 05","name":"SCADA"}
        e2={**base,"id":42,"plant":"Example Site 06","name":"SCADA","proxy_port":8100}
        token=appmod.guacamole_token("portal-user",[(e1,"example-site-05"),(e2,"example-site-06")],now_ms=1000000)
        raw=Cipher(algorithms.AES(bytes.fromhex(appmod.GUAC_JSON_KEY)),modes.CBC(bytes(16))).decryptor().update(base64.b64decode(token))
        unpad=PKCS7(128).unpadder(); clear=unpad.update(raw)+unpad.finalize(); data=json.loads(clear[32:])
        self.assertEqual(set(data["connections"]),{appmod.guacamole_connection_name(e1),appmod.guacamole_connection_name(e2)})
        self.assertEqual(data["connections"][appmod.guacamole_connection_name(e2)]["parameters"]["hostname"],"vpn-example-site-06")

    def test_parse_rdp_content_imports_remoteapp_and_endpoint(self):
        rdp=("full address:s:203.0.113.14\r\nserver port:i:3389\r\nremoteapplicationmode:i:1\r\nremoteapplicationprogram:s:||DemoApp2\r\nremoteapplicationname:s:DemoApp2\r\n").encode("utf-16")
        parsed=appmod.parse_rdp_content(rdp)
        self.assertEqual(parsed["kind"],"RDP")
        self.assertEqual(parsed["real_ip"],"203.0.113.14")
        self.assertEqual(parsed["real_port"],"3389")
        self.assertEqual(parsed["rdp_remote_app"],"DemoApp2")
        self.assertEqual(parsed["name"],"DemoApp2")

    def test_guacamole_token_launches_configured_remoteapp(self):
        import base64, json
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7
        appmod.GUAC_JSON_KEY = hashlib.sha256(b"synthetic-guac-json-key").hexdigest()[:32]
        e={"id":31,"plant":"Example Site 06","name":"DemoApp","proxy_port":8099,"rdp_username_enc":"","rdp_password_enc":"","rdp_domain_enc":"","rdp_remote_app":"DemoApp3"}
        token=appmod.guacamole_token("portal-user",[(e,"example-site-06")],now_ms=1000000)
        raw=Cipher(algorithms.AES(bytes.fromhex(appmod.GUAC_JSON_KEY)),modes.CBC(bytes(16))).decryptor().update(base64.b64decode(token))
        unpad=PKCS7(128).unpadder(); clear=unpad.update(raw)+unpad.finalize()
        data=json.loads(clear[32:])
        self.assertEqual(data["connections"][appmod.guacamole_connection_name(e)]["parameters"]["remote-app"],"||DemoApp3")

    def test_web_proxy_rewrites_private_absolute_redirects_to_public_host(self):
        rules=appmod.web_redirect_rules("203.0.113.63","80","http://203.0.113.179:8085/")
        self.assertIn("http-request set-var(txn.public_host) req.hdr(Host)",rules)
        self.assertIn(r"^https?://203\.0\.113\.63(?::80)?(/.*)?$",rules)
        self.assertIn(r"http://%[var(txn.public_host)]\1",rules)
        self.assertNotIn("Content-Security-Policy",rules)

if __name__=="__main__": unittest.main()
