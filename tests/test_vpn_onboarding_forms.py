import importlib,io,json,os,sqlite3,sys,tempfile,unittest
from unittest import mock
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
TMP=tempfile.TemporaryDirectory();os.environ['PANEL_DATA_DIR']=TMP.name;os.environ['PANEL_DB']=str(Path(TMP.name)/'panel.db');os.environ['PROJECT_DIR']=str(Path(TMP.name)/'project');os.environ['PANEL_BOOTSTRAP_ADMIN_PASSWORD']='synthetic-bootstrap-only-123';sys.path.insert(0,str(ROOT/'panel-app'))
import app as panel
FIXTURE=(ROOT/'tests/fixtures/forticlient-safe-synthetic.xml').read_bytes()
class OnboardingFormTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  panel.app.config.update(TESTING=True);cls.client=panel.app.test_client()
  with cls.client.session_transaction() as s:s['uid']=1
 def setUp(self):
  with panel.app.app_context():
   conn=panel.db();conn.execute("delete from forticlient_import_staging");conn.execute("delete from openvpn_import_staging");conn.execute("delete from vpns where slug like 'new-%' or slug='form-base'")
   conn.execute("insert into vpns(plant,slug,host,port,username,password_enc,active,created_at,vpn_type,ipsec_engine) values(?,?,?,?,?,?,?,?,?,?)",('Synthetic Form Site','form-base','vpn.example.test','443','synthetic-user','',1,'now','ssl','libreswan'));conn.commit()
 def test_ipsec_get_is_import_first_and_manual_is_advanced(self):
  body=self.client.get('/admin/vpns/new/ipsec').get_data(as_text=True)
  self.assertIn('multipart/form-data',body);self.assertIn('name="forticlient_file"',body);self.assertIn('Configuración manual avanzada',body);self.assertNotIn('name="ipsec_engine"',body)
  manual=self.client.get('/admin/vpns/new/ipsec?mode=manual').get_data(as_text=True);self.assertIn('name=ipsec_engine',manual);self.assertNotIn('name=validation_target_ip',manual);self.assertNotIn('name=validation_target_port',manual)
 def test_ssl_certificate_checkbox_is_scoped_and_checked_by_default(self):
  ssl=self.client.get('/admin/vpns/new/ssl?mode=manual').get_data(as_text=True)
  self.assertIn('name=accept_gateway_certificate',ssl);self.assertIn('Validación de certificado',ssl);self.assertRegex(ssl,r'name=accept_gateway_certificate[^>]*checked')
  ipsec=self.client.get('/admin/vpns/new/ipsec?mode=manual').get_data(as_text=True);self.assertNotIn('name=accept_gateway_certificate',ipsec)
 def test_ssl_values_persist_explicit_certificate_acceptance(self):
  checked=panel.vpn_vals({'vpn_type':'ssl','plant':'New SSL','slug':'new-ssl','host':'vpn.example.test','port':'443','username':'u','password':'p','accept_gateway_certificate':'1'},None)
  unchecked=panel.vpn_vals({'vpn_type':'ssl','plant':'New SSL','slug':'new-ssl','host':'vpn.example.test','port':'443','username':'u','password':'p'},None)
  self.assertEqual(checked['accept_gateway_certificate'],1);self.assertEqual(unchecked['accept_gateway_certificate'],0)
 def test_imported_ssl_review_defaults_certificate_acceptance(self):
  profile={'kind':'ssl','profile_name':'Synthetic SSL','host':'vpn.example.test','port':'443'}
  body=panel.imported_review_form('ssl','x'*43,0,profile)
  self.assertRegex(body,r'name="accept_gateway_certificate"[^>]*checked')
  values=panel.imported_profile_values(profile,{'plant':'New SSL','slug':'new-ssl','username':'u','password':'p','accept_gateway_certificate':'1'})
  self.assertEqual(values['accept_gateway_certificate'],1)
 def csrf(self,kind='ipsec'):
  self.client.get('/admin/vpns/new/'+kind)
  with self.client.session_transaction() as s:return s['_onboarding_csrf']
 def upload(self,kind='ipsec'):
  return self.client.post('/admin/vpns/new/'+kind,data={'_csrf':self.csrf(kind),'forticlient_file':(io.BytesIO(FIXTURE),'vpn.conf'),'onboarding_action':'upload'},content_type='multipart/form-data')
 def test_upload_lists_only_profiles_for_selected_type_without_xml_or_secrets(self):
  r=self.upload();self.assertEqual(r.status_code,200);body=r.get_data(as_text=True)
  self.assertIn('Synthetic IKEv1',body);self.assertIn('Synthetic IKEv2',body);self.assertNotIn('Synthetic SSL',body);self.assertIn('name="forticlient_stage_token"',body)
  for x in ('SYNTHETIC-CIPHERTEXT','EncX SYNTHETIC','preshared_key'):self.assertNotIn(x,body)
 def test_select_renders_review_and_separate_secret_fields(self):
  body=self.upload().get_data(as_text=True);token=body.split('name="forticlient_stage_token" value="',1)[1].split('"',1)[0]
  r=self.client.post('/admin/vpns/new/ipsec',data={'_csrf':self.csrf(),'onboarding_action':'select','forticlient_stage_token':token,'profile_index':'0'});self.assertEqual(r.status_code,200);body=r.get_data(as_text=True)
  for field in ('name="psk"','name="username"','name="password"'):self.assertIn(field,body)
  self.assertNotIn('name="validation_target_ip"',body);self.assertNotIn('name="validation_target_port"',body)
  self.assertIn('Perfil FortiClient',body);self.assertIn('<details',body);self.assertIn('name="ipsec_engine"',body)
 def test_final_creates_inactive_draft_and_consumes_stage(self):
  body=self.upload().get_data(as_text=True);token=body.split('name="forticlient_stage_token" value="',1)[1].split('"',1)[0]
  data={'_csrf':self.csrf(),'onboarding_action':'create','forticlient_stage_token':token,'profile_index':'0','plant':'New Plant','slug':'new-plant','username':'synthetic-user','password':'synthetic-pass','psk':'synthetic-psk','auto_activate':'1','ipsec_engine':'strongswan'}
  r=self.client.post('/admin/vpns/new/ipsec',data=data);self.assertEqual(r.status_code,302)
  with sqlite3.connect(os.environ['PANEL_DB']) as c:
   c.row_factory=sqlite3.Row;v=c.execute("select * from vpns where slug='new-plant'").fetchone();self.assertIsNotNone(v);self.assertEqual((v['active'],v['onboarding_state'],v['validation_target_ip'],v['validation_target_port']),(0,'draft','',None));self.assertEqual(json.loads(v['phase1_proposals_json']),[{'encryption':'aes256','integrity':'sha512'}]);self.assertEqual(c.execute('select count(*) from forticlient_import_staging where token=?',(token,)).fetchone()[0],0)
 def test_legacy_target_fields_are_ignored_and_stage_is_consumed(self):
  body=self.upload().get_data(as_text=True);token=body.split('name="forticlient_stage_token" value="',1)[1].split('"',1)[0]
  data={'_csrf':self.csrf(),'onboarding_action':'create','forticlient_stage_token':token,'profile_index':'0','plant':'New Bad','slug':'new-bad','username':'secret-user','password':'secret-password','psk':'secret-psk','validation_target_ip':'not-an-ip','validation_target_port':'3389','ipsec_engine':'strongswan'}
  r=self.client.post('/admin/vpns/new/ipsec',data=data);self.assertEqual(r.status_code,302)
  with sqlite3.connect(os.environ['PANEL_DB']) as c:
   row=c.execute("select validation_target_ip,validation_target_port from vpns where slug='new-bad'").fetchone();self.assertEqual(row,('',None));self.assertEqual(c.execute('select count(*) from forticlient_import_staging where token=?',(token,)).fetchone()[0],0)
 def test_ssl_upload_and_access_forms_omit_validation_target(self):
  body=self.upload('ssl').get_data(as_text=True);self.assertIn('Synthetic SSL',body);self.assertNotIn('Synthetic IKEv1',body)
  for kind in ('pptp','openvpn'):
   b=self.client.get('/admin/vpns/new/'+kind).get_data(as_text=True);self.assertNotIn('name=validation_target_ip',b);self.assertNotIn('name=validation_target_port',b)
 def test_rejects_missing_csrf_before_parsing_upload(self):
  r=self.client.post('/admin/vpns/new/ipsec',data={'onboarding_action':'upload','forticlient_file':(io.BytesIO(FIXTURE),'vpn.conf')},content_type='multipart/form-data');self.assertEqual(r.status_code,400);self.assertIn('sesión del formulario',r.get_data(as_text=True))
 def test_delete_only_records_durable_intent_without_immediate_docker(self):
  with sqlite3.connect(os.environ['PANEL_DB']) as c:i=c.execute('select id from vpns order by id limit 1').fetchone()[0]
  with mock.patch.object(panel.subprocess,'run') as run:r=self.client.post(f'/admin/vpns/{i}/delete',data={'_csrf':self.csrf()})
  self.assertEqual(r.status_code,302);run.assert_not_called()
  with sqlite3.connect(os.environ['PANEL_DB']) as c:self.assertEqual(c.execute('select active,onboarding_state,validation_code from vpns where id=?',(i,)).fetchone(),(0,'deleting','deleting'))
 def test_reload_requires_csrf_and_never_calls_legacy_apply(self):
  with sqlite3.connect(os.environ['PANEL_DB']) as c:i=c.execute('select id from vpns order by id limit 1').fetchone()[0];c.execute('update vpns set active=1 where id=?',(i,));c.commit()
  with mock.patch.object(panel,'apply_vpn') as apply:self.assertEqual(self.client.post(f'/admin/vpns/{i}/reload',data={}).status_code,400);apply.assert_not_called()
 def test_generate_get_is_gone_and_post_is_non_mutating(self):
  with sqlite3.connect(os.environ['PANEL_DB']) as c:i=c.execute('select id from vpns order by id limit 1').fetchone()[0];c.execute('update vpns set active=1 where id=?',(i,));c.commit()
  with mock.patch.object(panel,'apply_vpn',return_value=(True,'','')):self.assertEqual(self.client.get(f'/admin/vpns/{i}/generate').status_code,405)
  with mock.patch.object(panel,'apply_vpn') as apply:r=self.client.post(f'/admin/vpns/{i}/generate',data={'_csrf':self.csrf()})
  self.assertEqual(r.status_code,410);apply.assert_not_called()
 def test_active_edit_is_rejected_without_db_or_runtime_mutation(self):
  with sqlite3.connect(os.environ['PANEL_DB']) as c:i=c.execute('select id from vpns where active=1 order by id limit 1').fetchone()[0];before=c.execute('select * from vpns where id=?',(i,)).fetchone()
  with mock.patch.object(panel,'apply_vpn') as apply:r=self.client.post(f'/admin/vpns/{i}/edit',data={'_csrf':self.csrf()})
  self.assertEqual(r.status_code,409);apply.assert_not_called()
  with sqlite3.connect(os.environ['PANEL_DB']) as c:self.assertEqual(c.execute('select * from vpns where id=?',(i,)).fetchone(),before)
 def test_invalid_draft_edit_does_not_destroy_artifacts_first(self):
  with sqlite3.connect(os.environ['PANEL_DB']) as c:i=c.execute('select id from vpns order by id limit 1').fetchone()[0];c.execute("update vpns set active=0,onboarding_state='draft' where id=?",(i,));c.commit()
  with mock.patch.object(panel,'prepare_draft_edit') as prep:r=self.client.post(f'/admin/vpns/{i}/edit',data={'_csrf':self.csrf()})
  self.assertEqual(r.status_code,400);prep.assert_not_called()
 def test_manual_activation_is_post_csrf_and_only_rearms_reconciliation(self):
  with sqlite3.connect(os.environ['PANEL_DB']) as c:
   i=c.execute("select id from vpns order by id limit 1").fetchone()[0];c.execute("update vpns set active=0,auto_activate=0,onboarding_state='verified_pending_activation',validation_code='verified_pending_activation' where id=?",(i,));c.commit()
  self.assertEqual(self.client.post(f'/admin/vpns/{i}/activate',data={}).status_code,400)
  r=self.client.post(f'/admin/vpns/{i}/activate',data={'_csrf':self.csrf()});self.assertEqual(r.status_code,302)
  with sqlite3.connect(os.environ['PANEL_DB']) as c:self.assertEqual(c.execute('select active,auto_activate,onboarding_state,validation_code from vpns where id=?',(i,)).fetchone(),(0,1,'installed','manual_activation_requested'))
 def test_forticlient_save_and_stage_consume_are_one_transaction(self):
  body=self.upload().get_data(as_text=True);token=body.split('name="forticlient_stage_token" value="',1)[1].split('"',1)[0]
  data={'_csrf':self.csrf(),'onboarding_action':'create','forticlient_stage_token':token,'profile_index':'0','plant':'New Atomic','slug':'new-atomic','username':'synthetic-user','password':'synthetic-pass','psk':'synthetic-psk','auto_activate':'1','ipsec_engine':'strongswan'}
  with mock.patch.object(panel,'consume_stage',side_effect=sqlite3.IntegrityError('synthetic consume failure')):r=self.client.post('/admin/vpns/new/ipsec',data=data)
  self.assertEqual(r.status_code,400)
  with sqlite3.connect(os.environ['PANEL_DB']) as c:
   self.assertEqual(c.execute("select count(*) from vpns where slug='new-atomic'").fetchone()[0],0);self.assertEqual(c.execute('select count(*) from forticlient_import_staging where token=?',(token,)).fetchone()[0],1)
 def test_openvpn_stage_survives_parse_failure_before_successful_draft(self):
  profile=b'client\nremote 192.0.2.10 1194\nauth-user-pass\n';parsed={'host':'192.0.2.10','port':1194,'proto':'udp','routes':['198.51.0.0/16'],'requires_auth':True,'requires_key_pass':False,'profile':profile.decode()}
  with panel.app.app_context():token=panel.stage_openvpn_import(panel.db(),'1',{'plant':'New OVPN','slug':'new-ovpn'},parsed,profile)
  data={'_csrf':self.csrf('openvpn'),'openvpn_stage_token':token,'plant':'New OVPN','slug':'new-ovpn','username':'u','password':'p'}
  with mock.patch.object(panel,'parse_openvpn_profile',side_effect=ValueError('synthetic parse failure')):r=self.client.post('/admin/vpns/new/openvpn',data=data)
  self.assertEqual(r.status_code,400)
  with sqlite3.connect(os.environ['PANEL_DB']) as c:self.assertEqual(c.execute('select count(*) from openvpn_import_staging where token=?',(token,)).fetchone()[0],1)

 def test_legacy_apply_never_probes_certificate_without_opt_in(self):
  with panel.app.app_context():
   v=dict(panel.db().execute('select * from vpns order by id limit 1').fetchone());v.update(vpn_type='ssl',trusted_cert_enc='',accept_gateway_certificate=0)
   with mock.patch.object(panel,'ensure_haproxy'),mock.patch.object(panel,'gen_ssl'),mock.patch.object(panel,'publish_plant'),mock.patch.object(panel,'wait_vpn_runtime',return_value=(False,'','offline')),mock.patch.object(panel.time,'sleep'),mock.patch.object(panel.subprocess,'run') as run:panel.apply_vpn(v)
  run.assert_not_called()
 def test_all_admin_mutations_are_globally_csrf_protected(self):
  self.assertEqual(self.client.post('/admin/equipment/999/delete').status_code,400);self.assertEqual(self.client.post('/admin/users/new',data={'username':'x'}).status_code,400)
 def test_page_injects_csrf_into_legacy_equipment_form(self):
  r=self.client.get('/admin/equipment/new');self.assertEqual(r.status_code,200);self.assertIn(b'name=_csrf',r.data)

if __name__=='__main__':unittest.main()
