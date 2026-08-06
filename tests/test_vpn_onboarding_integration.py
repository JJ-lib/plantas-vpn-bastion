import os,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];TMP=tempfile.TemporaryDirectory();os.environ['PANEL_DATA_DIR']=TMP.name;os.environ['PANEL_DB']=str(Path(TMP.name)/'panel.db');os.environ['PROJECT_DIR']=str(Path(TMP.name)/'project');os.environ['PANEL_BOOTSTRAP_ADMIN_PASSWORD']='synthetic-bootstrap-only-123';sys.path.insert(0,str(ROOT/'panel-app'));import app as panel
class IntegrationTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  with panel.app.app_context():
   c=panel.db();c.execute("insert into vpns(plant,slug,host,port,vpn_type,active,onboarding_state,validation_stage,validation_code,validation_detail) values('Draft plant','draft-plant','192.0.2.10','500','ipsec',0,'draft','local','pending','Pendiente de validación local.')");c.commit();cls.vid=c.execute("select id from vpns where slug='draft-plant'").fetchone()[0]
 def setUp(self):
  self.client=panel.app.test_client()
  with self.client.session_transaction() as s:s['uid']=1;s['_onboarding_csrf']='test-csrf-token'
 def test_admin_list_renders_draft_state_without_runtime_probe_or_apply_actions(self):
  old=panel.vpn_runtime
  def probe(v):
   if v['slug']=='draft-plant':raise AssertionError('draft runtime probe')
   return False,'','offline'
  panel.vpn_runtime=probe
  try:r=self.client.get('/admin/vpns')
  finally:panel.vpn_runtime=old
  body=r.get_data(as_text=True);self.assertEqual(r.status_code,200);self.assertIn('Pendiente de validación local.',body);self.assertNotIn(f'/admin/vpns/{self.vid}/generate',body);self.assertNotIn(f'/admin/vpns/{self.vid}/reload',body)
 def test_generate_and_reload_refuse_inactive_draft_without_apply(self):
  old=panel.apply_vpn;panel.apply_vpn=lambda v:(_ for _ in ()).throw(AssertionError('apply bypass'))
  try:
   self.assertEqual(self.client.get(f'/admin/vpns/{self.vid}/generate').status_code,405);self.assertEqual(self.client.post(f'/admin/vpns/{self.vid}/reload').status_code,400)
  finally:panel.apply_vpn=old
 def test_editing_inactive_draft_resets_it_without_apply(self):
  with panel.app.app_context():row=panel.db().execute('select * from vpns where id=?',(self.vid,)).fetchone()
  old_vals,old_save,old_apply=panel.vpn_vals,panel.save_vpn,panel.apply_vpn;panel.vpn_vals=lambda *a,**k:{};panel.save_vpn=lambda *a,**k:row;panel.apply_vpn=lambda v:(_ for _ in ()).throw(AssertionError('apply bypass'))
  try:r=self.client.post(f'/admin/vpns/{self.vid}/edit',data={'_csrf':'test-csrf-token'})
  finally:panel.vpn_vals, panel.save_vpn, panel.apply_vpn=old_vals,old_save,old_apply
  self.assertEqual(r.status_code,302)
 def test_edit_without_csrf_fails_before_mutating_draft(self):
  with panel.app.app_context():before=tuple(panel.db().execute('select onboarding_state,onboarding_revision from vpns where id=?',(self.vid,)).fetchone())
  r=self.client.post(f'/admin/vpns/{self.vid}/edit',data={});self.assertEqual(r.status_code,400)
  with panel.app.app_context():after=tuple(panel.db().execute('select onboarding_state,onboarding_revision from vpns where id=?',(self.vid,)).fetchone())
  self.assertEqual(after,before)
 def test_delete_without_csrf_fails_before_mutating_draft(self):
  r=self.client.post(f'/admin/vpns/{self.vid}/delete',data={});self.assertEqual(r.status_code,400)
  with panel.app.app_context():row=panel.db().execute('select onboarding_state from vpns where id=?',(self.vid,)).fetchone()
  self.assertIsNotNone(row);self.assertNotEqual(row[0],'deleting')
 def test_candidate_image_and_reconciler_service_include_all_modules(self):
  app_source=(ROOT/'panel-app/app.py').read_text();dockerfile=(ROOT/'panel-app/Dockerfile').read_text();compose=(ROOT/'docker-compose.yml').read_text();requirements=(ROOT/'panel-app/requirements.txt').read_text();self.assertIn('defusedxml==0.7.1',requirements);self.assertIn('COPY *.py ./',dockerfile);self.assertIn('vpn-reconciler:',compose);self.assertIn('["python", "-m", "vpn_reconciler"',compose);self.assertIn('image: ${PANEL_IMAGE:?Set PANEL_IMAGE to an immutable image reference}',compose);self.assertNotIn('image: plantas-panel:latest',compose);self.assertNotIn('INITIAL_ADMIN_PASSWORD:',compose);self.assertIn("WHERE active=1 AND onboarding_state IN ('active','online')",app_source);self.assertIn('La VPN dejó de estar activa antes de publicar',app_source)
if __name__=='__main__':unittest.main()
