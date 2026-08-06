import json,sqlite3,sys,tempfile,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'panel-app'))
from vpn_onboarding import ensure_onboarding_schema,stage_profiles,load_stage,consume_stage,retry_delay,set_validation_state

PROFILE={'kind':'ipsec','profile_name':'Safe','host':'vpn.example.test','port':'500','phase1_proposals':[{'encryption':'aes256','integrity':'sha256'}],'source':{'version':'7.4.3'}}
def encrypt(x):return 'sealed:'+x[::-1]
def decrypt(x):return x[len('sealed:'):][::-1] if x.startswith('sealed:') else ''
class OnboardingModelTests(unittest.TestCase):
 def conn(self):
  c=sqlite3.connect(':memory:');c.row_factory=sqlite3.Row;c.execute('CREATE TABLE vpns(id INTEGER PRIMARY KEY,plant TEXT,slug TEXT,active INTEGER)');c.execute("INSERT INTO vpns VALUES(1,'Existing','existing',1)");return c
 def test_migration_is_idempotent_and_preserves_existing_as_active(self):
  c=self.conn();ensure_onboarding_schema(c);ensure_onboarding_schema(c);cols={r[1] for r in c.execute('pragma table_info(vpns)')}
  for name in ('onboarding_state','validation_stage','validation_code','validation_detail','validation_target_ip','validation_target_port','next_retry_at','last_checked_at','retry_count','auto_activate','accept_gateway_certificate','profile_source','phase1_proposals_json','phase2_proposals_json'):self.assertIn(name,cols)
  self.assertEqual(c.execute('select onboarding_state from vpns where id=1').fetchone()[0],'active');self.assertEqual(c.execute('pragma busy_timeout').fetchone()[0],5000)
 def test_stage_is_owner_bound_expiring_encrypted_and_one_use(self):
  c=self.conn();ensure_onboarding_schema(c);token=stage_profiles(c,'1',[PROFILE],encrypt,now=1000)
  raw=c.execute('select profiles_enc from forticlient_import_staging').fetchone()[0];self.assertNotIn('vpn.example.test',raw)
  self.assertIsNone(load_stage(c,'2',token,decrypt,now=1001));self.assertEqual(load_stage(c,'1',token,decrypt,now=1001),[PROFILE]);self.assertIsNone(load_stage(c,'1',token,decrypt,now=1901))
  token=stage_profiles(c,'1',[PROFILE],encrypt,now=2000);self.assertTrue(consume_stage(c,'1',token));self.assertIsNone(load_stage(c,'1',token,decrypt,now=2001));self.assertFalse(consume_stage(c,'1',token))
 def test_stage_rejects_secret_material_and_bad_token(self):
  c=self.conn();ensure_onboarding_schema(c)
  for bad in [dict(PROFILE,password='synthetic-invalid-password'),dict(PROFILE,ciphertext='x'),dict(PROFILE,extra='EncX x')]:
   with self.assertRaises(ValueError):stage_profiles(c,'1',[bad],encrypt,now=1)
  self.assertIsNone(load_stage(c,'1','../bad',decrypt,now=1))
 def test_retry_schedule_is_bounded_and_code_specific(self):
  self.assertEqual([retry_delay('peer_no_response',x) for x in range(6)],[60,300,900,1800,1800,1800]);self.assertEqual([retry_delay('target_tcp_unreachable',x) for x in range(5)],[60,300,900,900,900]);self.assertIsNone(retry_delay('authentication_failed',0))
 def test_state_transition_activates_only_active_result(self):
  c=self.conn();ensure_onboarding_schema(c);c.execute("update vpns set onboarding_state='draft',active=0,retry_count=0 where id=1")
  set_validation_state(c,1,{'state':'waiting_gateway','stage':'ike','code':'peer_no_response','public_message':'Gateway sin respuesta','retry':True},now=1000)
  r=c.execute('select * from vpns where id=1').fetchone();self.assertEqual((r['active'],r['retry_count'],r['next_retry_at']),(0,1,1060));self.assertEqual(r['validation_detail'],'Gateway sin respuesta')
  set_validation_state(c,1,{'state':'active','stage':'complete','code':'online','public_message':'Validada','retry':False},now=2000);r=c.execute('select * from vpns').fetchone();self.assertEqual((r['active'],r['onboarding_state'],r['next_retry_at']),(1,'active',None))
 def test_public_message_cannot_contain_secret_markers(self):
  c=self.conn();ensure_onboarding_schema(c)
  with self.assertRaises(ValueError):set_validation_state(c,1,{'state':'blocked','stage':'auth','code':'authentication_failed','public_message':'password=secret','retry':False},now=1)

class AutoActivateGateTests(unittest.TestCase):
 def test_online_does_not_activate_when_auto_activate_is_disabled(self):
  c=sqlite3.connect(':memory:');c.execute('create table vpns(id integer primary key,active integer,retry_count integer,auto_activate integer)');ensure_onboarding_schema(c);c.execute("insert into vpns(id,active,retry_count,auto_activate,onboarding_state) values(1,0,0,0,'validating')")
  set_validation_state(c,1,{'state':'online','stage':'target','code':'online','public_message':'verified','retryable':False},now=100)
  row=c.execute('select active,onboarding_state,validation_code from vpns where id=1').fetchone();self.assertEqual(row,(0,'verified_pending_activation','verified_pending_activation'))

if __name__=='__main__':unittest.main()
