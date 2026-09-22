import importlib.util, os, tempfile, unittest
from pathlib import Path
class WebPublicationModeTest(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();os.environ["PANEL_DB"]=str(Path(cls.tmp.name)/"panel.db");os.environ.setdefault("BASTION_PUBLIC_ORIGIN","https://192.0.2.1")
  spec=importlib.util.spec_from_file_location("panel_app_webmode",os.environ.get("PANEL_APP_UNDER_TEST",str(Path(__file__).resolve().parents[1] / "panel-app/app.py")));cls.app=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.app)
 @classmethod
 def tearDownClass(cls): cls.tmp.cleanup()
 def test_web_mode_is_migrated_validated_and_rendered(self):
  with self.app.app.app_context():
   cols={r[1] for r in self.app.db().execute("pragma table_info(equipment)")};self.assertTrue({"web_mode","web_effective_mode","web_diagnostic","web_proxy_port"} <= cols)
  base={"plant":"X","name":"WEB 1","kind":"WEB","real_ip":"192.0.2.5","real_port":"80","public_port":"19001"}
  self.assertEqual("auto",self.app.equipment_values(base)["web_mode"]);self.assertEqual("direct",self.app.equipment_values({**base,"web_mode":"direct"})["web_mode"])
  with self.assertRaisesRegex(ValueError,"tratamiento web"): self.app.equipment_values({**base,"web_mode":"invalid"})
  with self.app.app.app_context(): html=self.app.ef({**base,"web_mode":"rewrite_cache","web_diagnostic":"base HTML privada"})
  self.assertIn("name='web_mode'",html);self.assertIn("value='rewrite_cache' selected",html);self.assertIn("base HTML privada",html)
 def test_probe_analysis_selects_rewriter_only_for_private_origins(self):
  clean=self.app.analyze_web_probe("HTTP/1.1 200 OK\r\n","<html><script src='/app.js'></script></html>","192.0.2.63","80")
  self.assertEqual("direct",clean["effective_mode"])
  broken=self.app.analyze_web_probe("HTTP/1.1 200 OK\r\n","<base href='http://192.0.2.63/'><script src='http://192.0.2.63/app.js'></script>","192.0.2.63","80")
  self.assertEqual("rewrite_cache",broken["effective_mode"]);self.assertIn("base HTML privada",broken["diagnostic"])
  redirected=self.app.analyze_web_probe("HTTP/1.1 307\r\nLocation: http://192.0.2.63/login\r\n","","192.0.2.63","80")
  self.assertEqual("rewrite_cache",redirected["effective_mode"]);self.assertIn("redirección privada",redirected["diagnostic"])
  self.assertEqual("direct",self.app.resolve_web_mode("direct",broken)["effective_mode"])
  self.assertEqual("rewrite_cache",self.app.resolve_web_mode("auto",broken)["effective_mode"])
 def test_each_rewriter_has_an_isolated_listener_and_backend(self):
  rewrite={"id":8,"kind":"WEB","real_ip":"192.0.2.63","real_port":"80","web_effective_mode":"rewrite_cache","web_proxy_port":18008}
  direct={"id":9,"kind":"WEB","real_ip":"192.0.2.64","real_port":"80","web_effective_mode":"direct","web_proxy_port":None}
  cfg=self.app.render_webfix_config("example-site-04",[rewrite,direct])
  self.assertIn("listen 18008;",cfg);self.assertIn("proxy_pass http://192.0.2.63:80;",cfg);self.assertIn("eq_8_static",cfg)
  self.assertNotIn("192.0.2.64",cfg);self.assertNotIn("sub_filter_types text/html",cfg);self.assertEqual(2,cfg.count("        sub_filter \'"))
  self.assertEqual("127.0.0.1:18008",self.app.web_backend_target("Example Site 04",rewrite))
  self.assertEqual("192.0.2.64:80",self.app.web_backend_target("Example Site 04",direct))
 def test_non_default_origin_port_generates_specific_sub_filter(self):
  rewrite={"id":73,"kind":"WEB","real_ip":"192.0.2.248","real_port":"8088","web_effective_mode":"rewrite_cache","web_proxy_port":18073}
  cfg=self.app.render_webfix_config("example-site-11",[rewrite])
  self.assertIn("sub_filter 'http://192.0.2.248:8088/' '$scheme://$http_host/';",cfg)
 def test_compose_sidecar_is_added_and_removed_by_need(self):
  base='''services:
  vpn-demo:
    image: vpn
networks:
  bastion:
    external: true
'''
  added=self.app.update_webfix_compose_text(base,"demo",True)
  self.assertIn("webfix-demo:",added);self.assertIn("network_mode: 'service:vpn-demo'",added);self.assertIn("demo_web_cache:",added)
  removed=self.app.update_webfix_compose_text(added,"demo",False)
  self.assertNotIn("webfix-demo:",removed);self.assertNotIn("demo_web_cache:",removed)
 def test_auto_probe_executes_inside_the_selected_vpn_namespace(self):
  class Result:
   def __init__(self,text,code=0): self.stdout=text;self.stderr='';self.returncode=code
  calls=[]
  def runner(cmd,**kwargs):
   calls.append(cmd)
   return Result('HTTP/1.1 200 OK\r\n') if '-D' in cmd else Result('<base href="http://198.51.100.87/">')
  result=self.app.probe_web_equipment('demo','198.51.100.87','80','auto',runner=runner)
  self.assertEqual('rewrite_cache',result['effective_mode']);self.assertTrue(all(cmd[:3]==['docker','exec','vpn-demo'] for cmd in calls))
 def test_final_settings_persist_effective_mode_diagnostic_and_listener(self):
  with self.app.app.app_context():
   self.app.db().execute("insert or ignore into vpns(plant,slug,active) values('UNIT WEB','unit-test-web',1)");self.app.db().commit()
   original=self.app.probe_web_equipment
   self.app.probe_web_equipment=lambda *a,**k:{'effective_mode':'rewrite_cache','diagnostic':'base HTML privada'}
   try: result=self.app.finalize_web_settings({'plant':'UNIT WEB','kind':'WEB','real_ip':'192.0.2.5','real_port':'80','web_mode':'auto'},42)
   finally: self.app.probe_web_equipment=original
  self.assertEqual('rewrite_cache',result['web_effective_mode']);self.assertEqual(18042,result['web_proxy_port']);self.assertEqual('base HTML privada',result['web_diagnostic'])
if __name__=="__main__": unittest.main()
