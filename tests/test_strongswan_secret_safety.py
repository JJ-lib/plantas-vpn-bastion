import importlib.util
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
from werkzeug.datastructures import MultiDict

SPEC=importlib.util.spec_from_file_location("panelapp_secret_safety",os.environ.get("PANEL_APP_UNDER_TEST","/app/app.py"))
appmod=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(appmod)

def sample(ike="ikev2"):
    return {
        "id":12,"plant":"Test","slug":"test","host":"198.51.100.10","port":"500",
        "username":"dummy-user","password_enc":"pwd","psk_enc":"psk","vpn_type":"ipsec",
        "ipsec_engine":"strongswan","ike_version":ike,"auth_mode":"eap-mschapv2-psk" if ike=="ikev2" else "psk-xauth",
        "aggressive":0,"phase1_enc":"aes256","phase1_auth":"sha512","dh_group":"14",
        "phase1_enc2":"aes256" if ike=="ikev2" else "","phase1_auth2":"sha256" if ike=="ikev2" else "",
        "dh_groups":"14,20" if ike=="ikev2" else "14","phase1_lifetime":"86400","dpd":1,"nat_traversal":1,
        "phase2_enc":"aes256","phase2_auth":"sha512","phase2_enc2":"aes256" if ike=="ikev2" else "",
        "phase2_auth2":"sha256" if ike=="ikev2" else "","phase2_lifetime":"43200","pfs":1,"pfs_group":"20" if ike=="ikev2" else "14",
        "local_id":"","remote_id":"","modecfg":"pull","remote_subnet":"0.0.0.0/0",
    }

class StrongSwanSecretSafetyTests(unittest.TestCase):
    def setup_tree(self):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);appmod.BASE=td.name
        Path(td.name,"configs/test").mkdir(parents=True);Path(td.name,"sites/test").mkdir(parents=True)
        return Path(td.name)

    def test_ikev2_quotes_and_backslashes_are_escaped(self):
        root=self.setup_tree();values={"psk":'dummy"psk\\tail',"pwd":'dummy"pwd\\tail'};appmod.dec=lambda key: values[key]
        appmod.gen_ikev2_eap(sample(),"test")
        lines=(root/"configs/test/ipsec.secrets").read_text().splitlines()
        self.assertEqual(lines[0],r'%any %any : PSK "dummy\"psk\\tail"')
        self.assertEqual(lines[1],r'"dummy-user" : EAP "dummy\"pwd\\tail"')

    def test_control_characters_fail_closed_before_writing(self):
        root=self.setup_tree();conf=root/"configs/test/ipsec.conf";secret=root/"configs/test/ipsec.secrets";conf.write_text("OLD-CONF");secret.write_text("OLD-SECRET")
        appmod.dec=lambda key: "dummy\nvalue" if key=="psk" else "dummy-value"
        with self.assertRaisesRegex(ValueError,"control"):
            appmod.gen_ikev2_eap(sample(),"test")
        self.assertEqual(conf.read_text(),"OLD-CONF");self.assertEqual(secret.read_text(),"OLD-SECRET");self.assertEqual({p.name for p in conf.parent.iterdir()},{"ipsec.conf","ipsec.secrets"})

    def test_ipsec_pair_replace_failure_rolls_back_both_files(self):
        root=self.setup_tree();conf=root/"configs/test/ipsec.conf";secret=root/"configs/test/ipsec.secrets";conf.write_text("OLD-CONF");secret.write_text("OLD-SECRET");appmod.dec=lambda key:"dummy-value"
        real_replace=appmod.os.replace
        def fail_secret_replace(src,dst):
            if str(dst).endswith("ipsec.secrets") and ".tmp-" in str(src): raise OSError("simulated secret replace failure")
            return real_replace(src,dst)
        with patch.object(appmod.os,"replace",side_effect=fail_secret_replace):
            with self.assertRaisesRegex(OSError,"simulated"):
                appmod.gen_ikev2_eap(sample(),"test")
        self.assertEqual(conf.read_text(),"OLD-CONF");self.assertEqual(secret.read_text(),"OLD-SECRET");self.assertEqual({p.name for p in conf.parent.iterdir()},{"ipsec.conf","ipsec.secrets"})

    def test_ikev1_generators_validate_before_replacing_pair(self):
        for engine in ("strongswan","libreswan"):
            root=self.setup_tree();conf=root/"configs/test/ipsec.conf";secret=root/"configs/test/ipsec.secrets";conf.write_text("OLD-CONF");secret.write_text("OLD-SECRET")
            appmod.dec=lambda key:"dummy\nvalue" if key=="psk" else "dummy-value";v=sample("ikev1");v["ipsec_engine"]=engine
            with self.assertRaisesRegex(ValueError,"control"): appmod.gen_ipsec(v,"test")
            self.assertEqual(conf.read_text(),"OLD-CONF");self.assertEqual(secret.read_text(),"OLD-SECRET")

    def test_invalid_legacy_algorithms_raise_valueerror_not_keyerror(self):
        self.setup_tree();appmod.dec=lambda key:"dummy-value";v=sample();v["dh_groups"]="14,999"
        with self.assertRaisesRegex(ValueError,"DH"):
            appmod.gen_ikev2_eap(v,"test")
        v=sample();v["phase1_auth2"]="invalid"
        with self.assertRaisesRegex(ValueError,"(?i)integridad"):
            appmod.gen_ikev2_eap(v,"test")

    def test_apply_vpn_reports_generation_error_without_exception(self):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);appmod.BASE=td.name
        with patch.object(appmod,"ensure_haproxy",lambda *args:None), patch.object(appmod,"gen_ipsec",lambda *args:(_ for _ in ()).throw(ValueError("dummy invalid profile"))):
            result=appmod.apply_vpn(sample())
        self.assertFalse(result[0]);self.assertIn("Configuración IPsec no válida",result[2])

    def test_private_writer_creates_mode_0600(self):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);path=Path(td.name,"private")
        old=os.umask(0)
        try: appmod.write_private_text(path,"dummy")
        finally: os.umask(old)
        self.assertEqual(path.stat().st_mode&0o777,0o600)

    def test_private_writer_replace_failure_preserves_existing_file(self):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);path=Path(td.name,"private");path.write_text("old")
        with patch.object(appmod.os,"replace",side_effect=OSError("dummy replace failure")):
            with self.assertRaises(OSError): appmod.write_private_text(path,"new")
        self.assertEqual(path.read_text(),"old")
        self.assertEqual([x.name for x in path.parent.iterdir()],["private"])

    def test_ikev1_rejects_multiple_fields_instead_of_ignoring_them(self):
        form=sample("ikev1");form.update({"password":"dummy-password","psk":"dummy-psk","exchange_mode":"main","nat_traversal":"1","dpd":"1","pfs":"1","remote_subnet":"0.0.0.0/0"})
        form["phase1_enc2"]="aes256";form["phase1_auth2"]="sha256"
        with self.assertRaisesRegex(ValueError,"solo.*IKEv2"):
            appmod.vpn_vals(form,forced_type="ipsec")
        form["phase1_enc2"]="";form["phase1_auth2"]="";form["dh_groups"]="14,20"
        with self.assertRaisesRegex(ValueError,"solo.*IKEv2"):
            appmod.vpn_vals(form,forced_type="ipsec")
        form["dh_groups"]="14";form["phase1_auth2"]="sha256"
        with self.assertRaisesRegex(ValueError,"solo.*IKEv2"):
            appmod.vpn_vals(form,forced_type="ipsec")
        form["phase1_auth2"]="";form["pfs"]="0";form["pfs_group"]="20"
        with self.assertRaisesRegex(ValueError,"solo.*IKEv2"):
            appmod.vpn_vals(form,forced_type="ipsec")
        normal=sample("ikev1");normal.update({"password":"dummy-password","psk":"dummy-psk","exchange_mode":"main","nat_traversal":"1","dpd":"1","pfs":"1","remote_subnet":"0.0.0.0/0"})
        normal.pop("dh_groups");normal.pop("pfs_group");self.assertEqual(appmod.vpn_vals(normal,forced_type="ipsec")["dh_group"],"14")
        for field,value in (("dh_groups","14"),("dh_groups","20"),("pfs_group","14")):
            forged=normal.copy();forged[field]=value
            with self.assertRaisesRegex(ValueError,"solo.*IKEv2"): appmod.vpn_vals(forged,forced_type="ipsec")
        for field,value in (("phase1_enc2","aes128"),("phase1_auth2","sha256"),("phase2_enc2","aes128"),("phase2_auth2","sha256")):
            polluted=MultiDict(normal.items());polluted.setlist(field,["",value])
            with self.assertRaisesRegex(ValueError,"solo.*IKEv2|repetirse"): appmod.vpn_vals(polluted,forced_type="ipsec")
        polluted=MultiDict(normal.items());polluted.setlist("pfs_group",["14","20"])
        with self.assertRaisesRegex(ValueError,"solo.*IKEv2|repetirse"): appmod.vpn_vals(polluted,forced_type="ipsec")
        ikev2=sample("ikev2");ikev2.update({"password":"dummy-password","psk":"dummy-psk","exchange_mode":"main","nat_traversal":"1","dpd":"1","pfs":"1","remote_subnet":"0.0.0.0/0"});ikev2.pop("dh_group")
        self.assertEqual(appmod.vpn_vals(ikev2,forced_type="ipsec")["dh_group"],"14")
        forged_ikev2=ikev2.copy();forged_ikev2["dh_group"]="14"
        with self.assertRaisesRegex(ValueError,"solo.*IKEv1"): appmod.vpn_vals(forged_ikev2,forced_type="ipsec")
        page=appmod.vf(sample("ikev1"),"ipsec")
        self.assertGreaterEqual(page.count("data-ikev2-only"),6);self.assertIn("data-ikev1-only",page);self.assertIn("<select name=dh_group>",page);self.assertNotIn("type=hidden name=dh_group",page);self.assertIn("x.disabled=!on",page)

    def test_scalar_parameter_pollution_is_rejected(self):
        normal=sample("ikev1");normal.update({"password":"dummy-password","psk":"dummy-psk","exchange_mode":"main","nat_traversal":"1","dpd":"1","pfs":"1","remote_subnet":"0.0.0.0/0"});normal.pop("dh_groups");normal.pop("pfs_group")
        for field,values in (("dh_group",["5","999"]),("ike_version",["ikev1","ikev2"])):
            polluted=MultiDict(normal.items());polluted.setlist(field,values)
            with self.assertRaisesRegex(ValueError,"repet"): appmod.vpn_vals(polluted,forced_type="ipsec")
        ikev2=sample("ikev2");ikev2.update({"password":"dummy-password","psk":"dummy-psk","exchange_mode":"main","nat_traversal":"1","dpd":"1","pfs":"1","remote_subnet":"0.0.0.0/0"});ikev2.pop("dh_group")
        for field,values in (("pfs_group",["20","999"]),("phase1_enc2",["aes256","invalid"])):
            polluted=MultiDict(ikev2.items());polluted.setlist(field,values)
            with self.assertRaisesRegex(ValueError,"repet"): appmod.vpn_vals(polluted,forced_type="ipsec")

    def test_libreswan_secrets_use_shared_escaping_and_private_writer(self):
        root=self.setup_tree();values={"psk":'dummy"psk\\tail',"pwd":'dummy"pwd\\tail'};appmod.dec=lambda key:values[key]
        v=sample("ikev1");v["ipsec_engine"]="libreswan";appmod.gen_ipsec(v,"test")
        lines=(root/"configs/test/ipsec.secrets").read_text().splitlines()
        self.assertEqual(lines[0],r'%any 198.51.100.10 : PSK "dummy\"psk\\tail"')
        self.assertEqual(lines[1],r'"dummy-user" : XAUTH "dummy\"pwd\\tail"')
        self.assertEqual((root/"configs/test/ipsec.secrets").stat().st_mode&0o777,0o600)

    def test_publish_plant_is_scoped_and_does_not_rebuild_or_pre_remove(self):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);appmod.BASE=td.name
        Path(td.name,"configs/test").mkdir(parents=True);Path(td.name,"sites/test").mkdir(parents=True);Path(td.name,"sites/test/compose.yml").write_text("services: {}\n")
        class Rows(list):
            def fetchall(self): return self
        class FakeDb:
            def execute(self,*args,**kwargs): return Rows()
        appmod.db=lambda:FakeDb();appmod.vpn_for_plant=lambda plant:{"slug":"test","vpn_type":"ipsec"};appmod.render_haproxy_for_plant=lambda plant:("dummy",[]);appmod.update_compose_ports=lambda *args:None
        calls=[]
        def run(cmd,**kwargs): calls.append(cmd);return SimpleNamespace(returncode=0,stdout="",stderr="")
        with patch.object(appmod.subprocess,"run",side_effect=run): appmod.publish_plant("Test")
        self.assertFalse(any(cmd[:4]==["docker","rm","-f","vpn-test"] or (cmd[:3]==["docker","rm","-f"] and "vpn-test" in cmd[3:]) for cmd in calls))
        compose=next(cmd for cmd in calls if cmd[:2]==["docker","compose"] and "up" in cmd)
        self.assertIn("--no-deps",compose);self.assertIn("--force-recreate",compose);self.assertIn("--no-build",compose)
        self.assertIn("--pull",compose);self.assertIn("never",compose);self.assertNotIn("--build",compose)
        self.assertEqual(compose[-1],"vpn-test")
        config_index=next(i for i,cmd in enumerate(calls) if cmd[:2]==["docker","compose"] and "config" in cmd)
        runtime_indexes=[i for i,cmd in enumerate(calls) if cmd[:2]==["docker","run"] or cmd[:3]==["docker","rm","-f"]]
        self.assertTrue(all(config_index<i for i in runtime_indexes))
        class WebfixDb:
            def execute(self,*args,**kwargs): return Rows([{"kind":"WEB","web_effective_mode":"rewrite_cache"}])
        appmod.db=lambda:WebfixDb();appmod.render_webfix_config=lambda *args:"dummy";appmod.update_webfix_compose_text=lambda text,*args:text;calls.clear()
        with patch.object(appmod.subprocess,"run",side_effect=run): appmod.publish_plant("Test")
        config_index=next(i for i,cmd in enumerate(calls) if cmd[:2]==["docker","compose"] and "config" in cmd)
        nginx_index=next(i for i,cmd in enumerate(calls) if cmd[:2]==["docker","run"])
        up_index=next(i for i,cmd in enumerate(calls) if cmd[:2]==["docker","compose"] and "up" in cmd)
        self.assertLess(config_index,nginx_index);self.assertLess(nginx_index,up_index)
        nginx=calls[nginx_index];self.assertIn("--pull",nginx);self.assertEqual(nginx[nginx.index("--pull")+1],"never")

    def test_publish_rollback_removes_new_webfix_when_none_existed(self):
        root=self.setup_tree();compose=root/"sites/test/compose.yml";haproxy=root/"configs/test/haproxy.cfg";compose.write_bytes(b"services: {}\n");haproxy.write_bytes(b"OLD\n")
        class Rows(list):
            def fetchall(self):return self
        class FakeDb:
            def execute(self,*a,**k):return Rows()
        appmod.db=lambda:FakeDb();appmod.vpn_for_plant=lambda p:{"slug":"test","vpn_type":"ipsec"};appmod.render_haproxy_for_plant=lambda p:("NEW\n",[1]);appmod.render_webfix_config=lambda p:"WEB\n";calls=[];ups=0
        def run(cmd,**kwargs):
            nonlocal ups;calls.append(cmd)
            if 'config' in cmd:return SimpleNamespace(returncode=0,stdout="",stderr="")
            if 'up' in cmd:
                ups+=1;return SimpleNamespace(returncode=1 if ups==1 else 0,stdout="",stderr="")
            if cmd[:2]==['docker','inspect']:return SimpleNamespace(returncode=0,stdout="",stderr="")
            return SimpleNamespace(returncode=0,stdout="",stderr="")
        with patch.object(appmod.subprocess,"run",side_effect=run):
            with self.assertRaises(Exception):appmod.publish_plant("Test")
        self.assertTrue(any(cmd[:3]==['docker','rm','-f'] and cmd[-1]=='webfix-test' for cmd in calls));self.assertFalse((root/'configs/test/webfix.cfg').exists())

    def test_publish_preflight_failure_never_touches_runtime(self):
        root=self.setup_tree();compose=root/"sites/test/compose.yml";haproxy=root/"configs/test/haproxy.cfg";compose.write_bytes(b"services: {}\n");haproxy.write_bytes(b"OLD\n")
        class Rows(list):
            def fetchall(self):return self
        class FakeDb:
            def execute(self,*args,**kwargs):return Rows()
        appmod.db=lambda:FakeDb();appmod.vpn_for_plant=lambda plant:{"slug":"test","vpn_type":"ipsec"};appmod.render_haproxy_for_plant=lambda plant:("NEW\n",[]);calls=[]
        def run(cmd,**kwargs):calls.append(cmd);return SimpleNamespace(returncode=1,stdout="",stderr="")
        with patch.object(appmod.subprocess,"run",side_effect=run):
            with self.assertRaisesRegex(Exception,"staged inválida"):appmod.publish_plant("Test")
        self.assertEqual(compose.read_bytes(),b"services: {}\n");self.assertEqual(haproxy.read_bytes(),b"OLD\n");self.assertFalse(any('up' in cmd for cmd in calls))

    def test_publish_failure_restores_all_files_byte_for_byte(self):
        root=self.setup_tree();compose=root/"sites/test/compose.yml";haproxy=root/"configs/test/haproxy.cfg";webfix=root/"configs/test/webfix.conf";compose.write_bytes(b"services: {}\n");haproxy.write_bytes(b"OLD-HAPROXY\n");webfix.write_bytes(b"OLD-WEBFIX\n")
        class Rows(list):
            def fetchall(self):return self
        class FakeDb:
            def execute(self,*args,**kwargs):return Rows()
        appmod.db=lambda:FakeDb();appmod.vpn_for_plant=lambda plant:{"slug":"test","vpn_type":"ipsec"};appmod.render_haproxy_for_plant=lambda plant:("NEW-HAPROXY\n",[])
        ups=[1,0]
        def run(cmd,**kwargs):
            rc=ups.pop(0) if "up" in cmd else 0
            return SimpleNamespace(returncode=rc,stdout="",stderr="")
        with patch.object(appmod.subprocess,"run",side_effect=run):
            with self.assertRaisesRegex(Exception,"runtime exacto"):appmod.publish_plant("Test")
        self.assertEqual(compose.read_bytes(),b"services: {}\n");self.assertEqual(haproxy.read_bytes(),b"OLD-HAPROXY\n");self.assertEqual(webfix.read_bytes(),b"OLD-WEBFIX\n")
        self.assertFalse(any('.stage-' in p.name or '.rollback-' in p.name for p in root.rglob('*')))

    def test_empty_database_requires_external_admin_bootstrap_secret(self):
        self.assertTrue(hasattr(appmod,"ensure_bootstrap_admin"))
        con=sqlite3.connect(":memory:");con.execute("create table users(id integer primary key,username text unique,password_hash text,role text,active integer,created_at text)")
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaisesRegex(RuntimeError,"PANEL_BOOTSTRAP_ADMIN_PASSWORD"):
                appmod.ensure_bootstrap_admin(con,"2026-01-01T00:00:00")
        with patch.dict(os.environ,{"PANEL_BOOTSTRAP_ADMIN_PASSWORD":"dummy-bootstrap-value-123"},clear=True):
            appmod.ensure_bootstrap_admin(con,"2026-01-01T00:00:00")
        self.assertEqual(con.execute("select count(*) from users where username='admin'").fetchone()[0],1)

if __name__=="__main__":unittest.main()
