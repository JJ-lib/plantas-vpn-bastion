import sqlite3,tempfile,unittest,os,fcntl
from pathlib import Path
from vpn_onboarding import ensure_onboarding_schema
from vpn_reconciler import Dependencies,reconcile_once,start_spec,extract_certificate_digests
from vpn_validation import ValidationEvidence,ValidationResult
class ReconcilerTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.base=Path(self.t.name);os.environ['ONBOARDING_LOCK_DIR']=str(self.base/'locks');(self.base/'sites').mkdir();(self.base/'configs').mkdir();(self.base/'docker-compose.yml').write_text('services: {}');self.db=sqlite3.connect(':memory:');self.db.row_factory=sqlite3.Row;self.db.execute("create table vpns(id integer primary key,slug text unique,plant text,vpn_type text,ipsec_engine text,trusted_cert_enc text default '',active integer default 0)");ensure_onboarding_schema(self.db);self.calls=[];self.generated=[];self.activations=[];self.cleanups=[]
 def tearDown(self):self.db.close();self.t.cleanup()
 def add(self,slug='new-one',state='draft',code='pending',due=None,active=0,auto_activate=1,vpn_type='ipsec',accept_certificate=0,trusted_cert=''):
  self.db.execute('insert into vpns(slug,plant,vpn_type,ipsec_engine,trusted_cert_enc,active,onboarding_state,validation_code,validation_target_ip,validation_target_port,next_retry_at,auto_activate,accept_gateway_certificate) values(?,?,?,?,?,?,?,?,?,?,?,?,?)',(slug,slug,vpn_type,'strongswan',trusted_cert,active,state,code,'198.51.100.40',443,due,auto_activate,accept_certificate));self.db.commit()
 def deps(self,evidence=None,static=None,start_rc=0):
  evidence=evidence or ValidationEvidence(True,True,True,True,True,True,True,True,False,False);static=static or ValidationResult('validating','local','local_validated','ok',False)
  def generate(vpn,base):
   self.generated.append(vpn['slug']);pd=base/f'sites/{vpn["slug"]}';cd=base/f'configs/{vpn["slug"]}';pd.mkdir(exist_ok=True);cd.mkdir(exist_ok=True);(pd/'compose.yml').write_text('services: {}');(pd/'.onboarding-owner').write_text(vpn['generation_owner']);(cd/'.onboarding-owner').write_text(vpn['generation_owner'])
  def run(argv,timeout=0):self.calls.append(argv);return (1,'not found') if argv[:2]==['docker','inspect'] else (start_rc,'')
  def activate(conn,vpn,base,runner):self.activations.append(vpn['slug']);return ValidationResult('active','activation','active','VPN activada.',False)
  def cleanup(vpn,base,runner):
   import shutil
   self.cleanups.append(vpn['slug']);shutil.rmtree(base/f"configs/{vpn['slug']}",ignore_errors=True);shutil.rmtree(base/f"sites/{vpn['slug']}",ignore_errors=True)
  return Dependencies(generate=generate,static_validate=lambda vpn,base,runner:static,collect_runtime=lambda vpn,runner:evidence,runner=run,activate=activate,cleanup=cleanup)
 def row(self,slug='new-one'):return self.db.execute('select * from vpns where slug=?',(slug,)).fetchone()
 def test_extract_certificate_digests_accepts_only_exact_openfortivpn_hints(self):
  good='a'*64;other='b'*64
  logs=f'ERROR: use --trusted-cert {good} to trust it\ntrusted-cert = {good}\nnoise {other}'
  self.assertEqual(extract_certificate_digests(logs),{good})
 def test_expired_lease_is_recovered_but_fresh_lease_is_not_stolen(self):
  self.add();self.db.execute("update vpns set reconcile_lock_token='dead-worker',reconcile_lock_until=999 where slug='new-one'");self.db.commit();self.assertEqual(reconcile_once(self.db,self.base,1000,self.deps()),1);self.assertEqual(self.row()['active'],1)
  self.db.execute("update vpns set active=0,onboarding_state='installed',reconcile_lock_token='live-worker',reconcile_lock_until=2000 where slug='new-one'");self.db.commit();self.assertEqual(reconcile_once(self.db,self.base,1001,self.deps()),0)
 def test_web_flock_blocks_worker_for_same_slug(self):
  self.add();lockdir=Path(os.environ['ONBOARDING_LOCK_DIR']);lockdir.mkdir(parents=True,exist_ok=True);fd=os.open(lockdir/'new-one.lock',os.O_CREAT|os.O_RDWR,0o600);fcntl.flock(fd,fcntl.LOCK_EX)
  try:self.assertEqual(reconcile_once(self.db,self.base,1000,self.deps()),0);self.assertEqual(self.generated,[])
  finally:fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)
 def test_crash_during_owned_generation_is_cleaned_and_retried(self):
  self.add(state='validating',code='pending');owner='owned-crash';self.db.execute("update vpns set generation_phase='generating',generation_owner=? where slug='new-one'",(owner,));self.db.commit()
  for d in (self.base/'configs/new-one',self.base/'sites/new-one'):d.mkdir();(d/'.onboarding-owner').write_text(owner);(d/'partial').write_text('partial')
  reconcile_once(self.db,self.base,1000,self.deps());self.assertEqual(self.row()['active'],1);self.assertEqual(self.generated,['new-one'])
 def test_crash_generation_never_deletes_unowned_partial_directory(self):
  self.add(state='validating',code='pending');self.db.execute("update vpns set generation_phase='generating',generation_owner='owned-crash' where slug='new-one'");self.db.commit();d=self.base/'configs/new-one';d.mkdir();(d/'foreign').write_text('keep')
  reconcile_once(self.db,self.base,1000,self.deps());self.assertTrue((d/'foreign').exists());self.assertEqual(self.row()['validation_code'],'artifact_ownership_failed')
 def test_deleting_is_resumed_and_row_removed_after_owned_cleanup(self):
  self.add(state='deleting',code='deleting');self.assertEqual(reconcile_once(self.db,self.base,1000,self.deps()),1);self.assertIsNone(self.row());self.assertEqual(self.cleanups,['new-one'])
 def test_cleanup_failure_preserves_blocked_row_and_evidence(self):
  self.add(state='deleting',code='deleting');d=self.deps();d=Dependencies(d.generate,d.static_validate,d.collect_runtime,d.runner,d.activate,lambda vpn,base,runner:(_ for _ in ()).throw(RuntimeError('synthetic cleanup failure')));reconcile_once(self.db,self.base,1000,d);r=self.row();self.assertEqual((r['active'],r['onboarding_state'],r['validation_code']),(0,'blocked','cleanup_failed'))
 def test_start_spec_is_scoped_and_never_builds_or_removes(self):
  spec=start_spec(self.base,'new-one');flat=' '.join(spec);self.assertEqual(spec[-1],'vpn-new-one');self.assertIn('up -d --no-deps',flat);self.assertIn('--pull never',flat);self.assertIn('--no-build',flat);self.assertNotIn(' down ',flat);self.assertNotIn(' rm ',flat)
 def test_draft_generates_validates_starts_once_and_activates_only_after_online(self):
  self.add();d=self.deps();n=reconcile_once(self.db,self.base,1000,d);self.assertEqual(n,1);self.assertEqual(self.generated,['new-one']);self.assertEqual(self.row()['active'],1);starts=[' '.join(x) for x in self.calls if 'up' in x];self.assertEqual(len(starts),1);self.assertIn('--no-deps --pull never --no-build vpn-new-one',starts[0])
 def test_auto_activate_zero_stays_verified_pending_without_publication(self):
  self.add(auto_activate=0);reconcile_once(self.db,self.base,1000,self.deps());r=self.row();self.assertEqual((r['active'],r['onboarding_state'],r['validation_code']),(0,'verified_pending_activation','verified_pending_activation'));self.assertEqual(self.activations,[])
 def test_published_phase_recovers_activation_without_republishing(self):
  self.add();d=self.deps();reconcile_once(self.db,self.base,1000,d);self.assertEqual(self.activations,['new-one']);self.db.execute("update vpns set active=0,onboarding_state='validating',validation_code='runtime_probe_failed',next_retry_at=1001,publication_phase='published' where slug='new-one'");self.db.commit();reconcile_once(self.db,self.base,1001,d);self.assertEqual(self.activations,['new-one']);self.assertEqual((self.row()['active'],self.row()['publication_phase']),(1,'published'))
 def test_activation_failure_never_sets_active(self):
  self.add();d=self.deps();d=Dependencies(d.generate,d.static_validate,d.collect_runtime,d.runner,lambda conn,vpn,base,runner:ValidationResult('blocked','activation','activation_failed','No activada.',False),d.cleanup);reconcile_once(self.db,self.base,1000,d);r=self.row();self.assertEqual((r['active'],r['validation_code']),(0,'activation_failed'))
 def test_local_failure_never_starts_and_remains_inactive(self):
  self.add();bad=ValidationResult('draft','local','config_invalid','invalid',False);self.assertEqual(reconcile_once(self.db,self.base,1000,self.deps(static=bad)),1);self.assertEqual(self.row()['validation_code'],'config_invalid');self.assertEqual(self.row()['active'],0);self.assertFalse(any('up' in x for x in self.calls))
 def test_generation_failure_cleans_partial_slug_files_and_never_starts(self):
  self.add()
  def broken(vpn,base):
   (base/'configs/new-one').mkdir();(base/'sites/new-one').mkdir();raise ValueError('synthetic failure')
  d=self.deps();d=Dependencies(broken,d.static_validate,d.collect_runtime,d.runner,d.activate,d.cleanup);reconcile_once(self.db,self.base,1000,d);self.assertFalse((self.base/'configs/new-one').exists());self.assertFalse((self.base/'sites/new-one').exists());self.assertEqual(self.row()['validation_code'],'generation_failed');self.assertFalse(any('up' in x for x in self.calls))
 def test_retryable_offline_restarts_only_missing_owned_container(self):
  self.add();ev=ValidationEvidence(True,True,False,False,False,False,False,False,False,False);d=self.deps(evidence=ev);reconcile_once(self.db,self.base,1000,d);first_calls=len([x for x in self.calls if 'up' in x]);self.assertEqual(self.row()['validation_code'],'peer_no_response');due=self.row()['next_retry_at'];self.assertGreater(due,1000);self.db.execute('update vpns set next_retry_at=? where slug=?',(1000,'new-one'));self.db.commit();reconcile_once(self.db,self.base,1001,d);self.assertEqual(self.generated,['new-one']);self.assertEqual(len([x for x in self.calls if 'up' in x]),first_calls+1);self.assertEqual(self.row()['validation_code'],'peer_no_response')
 def test_runtime_startup_race_is_retryable(self):
  self.add();ev=ValidationEvidence(False,False,False,False,False,False,False,False,False,False);reconcile_once(self.db,self.base,1000,self.deps(evidence=ev));r=self.row();self.assertEqual(r['validation_code'],'container_not_running');self.assertIsNotNone(r['next_retry_at']);self.assertGreater(r['next_retry_at'],1000)
 def certificate_deps(self,digests,accept=True,trusted=''):
  ev=ValidationEvidence(True,False,False,False,False,False,False,False,False,False);d=self.deps(evidence=ev);base_run=d.runner
  text='\n'.join('--trusted-cert '+x for x in digests)
  def run(argv,timeout=0):
   if argv[:2]==['docker','logs']:return 0,text
   return base_run(argv,timeout)
  return Dependencies(d.generate,d.static_validate,d.collect_runtime,run,d.activate,d.cleanup,seal_certificate=lambda x:'sealed:'+x,unseal_certificate=lambda x:x[7:] if x.startswith('sealed:') else '')
 def test_ssl_opt_in_accepts_one_stable_certificate_and_regenerates_once(self):
  fp='a'*64;self.add(vpn_type='ssl',accept_certificate=1);d=self.certificate_deps([fp])
  reconcile_once(self.db,self.base,1000,d);r=self.row();self.assertEqual((r['active'],r['onboarding_state'],r['validation_code'],r['trusted_cert_enc'],r['onboarding_revision']),(0,'draft','pending','sealed:'+fp,1));self.assertEqual(self.cleanups,['new-one'])
  reconcile_once(self.db,self.base,1001,d);self.assertEqual(self.generated,['new-one','new-one']);self.assertEqual(self.cleanups,['new-one'])
 def test_ssl_without_opt_in_never_accepts_presented_certificate(self):
  self.add(vpn_type='ssl',accept_certificate=0);reconcile_once(self.db,self.base,1000,self.certificate_deps(['a'*64]));r=self.row();self.assertEqual((r['onboarding_state'],r['validation_code'],r['trusted_cert_enc']),('blocked','certificate_untrusted',''));self.assertEqual(self.cleanups,[])
 def test_ssl_ambiguous_certificate_hints_are_blocked(self):
  self.add(vpn_type='ssl',accept_certificate=1);reconcile_once(self.db,self.base,1000,self.certificate_deps(['a'*64,'b'*64]));self.assertEqual(self.row()['validation_code'],'certificate_ambiguous');self.assertEqual(self.cleanups,[])
 def test_ssl_existing_certificate_is_never_rotated_silently(self):
  old='a'*64;self.add(vpn_type='ssl',accept_certificate=1,trusted_cert='sealed:'+old);reconcile_once(self.db,self.base,1000,self.certificate_deps(['b'*64]));r=self.row();self.assertEqual((r['onboarding_state'],r['validation_code'],r['trusted_cert_enc']),('blocked','certificate_changed','sealed:'+old));self.assertEqual(self.cleanups,[])
 def test_auth_failure_is_blocked_without_retry(self):
  self.add();ev=ValidationEvidence(True,True,False,False,False,False,False,True,True,False);reconcile_once(self.db,self.base,1000,self.deps(evidence=ev));r=self.row();self.assertEqual((r['onboarding_state'],r['validation_code'],r['next_retry_at'],r['active']),('auth_failed','auth_failed',None,0))
 def test_manifest_tamper_blocks_retry(self):
  self.add();ev=ValidationEvidence(True,True,False,False,False,False,False,False,False,False);d=self.deps(evidence=ev);reconcile_once(self.db,self.base,1000,d);(self.base/'sites/new-one/compose.yml').write_text('tampered: true');self.db.execute("update vpns set next_retry_at=1000 where slug='new-one'");self.db.commit();reconcile_once(self.db,self.base,1001,d);self.assertEqual((self.row()['active'],self.row()['validation_code']),(0,'artifact_ownership_failed'))
 def test_revision_change_during_generation_prevents_activation(self):
  self.add();d=self.deps();orig=d.generate
  def racing(vpn,base):orig(vpn,base);self.db.execute('update vpns set onboarding_revision=onboarding_revision+1 where id=?',(vpn['id'],));self.db.commit()
  d=Dependencies(racing,d.static_validate,d.collect_runtime,d.runner,d.activate,d.cleanup);reconcile_once(self.db,self.base,1000,d);self.assertEqual(self.row()['active'],0)
 def test_retry_cannot_adopt_drift_as_new_baseline(self):
  self.add();ev=ValidationEvidence(True,True,False,False,False,False,False,True,False,False);d=self.deps(evidence=ev);reconcile_once(self.db,self.base,1000,d);self.assertEqual(self.row()['active'],0);self.db.execute("update vpns set next_retry_at=1001 where slug='new-one'");self.db.commit()
  base_run=d.runner
  def drift(argv,timeout=0):
   if argv[:3]==['docker','ps','-a']:return 0,'vpn-other\n'
   if argv[:2]==['docker','inspect'] and argv[-1]=='vpn-other':return 0,'other-id|1'
   return base_run(argv,timeout)
  d=Dependencies(d.generate,d.static_validate,d.collect_runtime,drift,d.activate,d.cleanup);reconcile_once(self.db,self.base,1001,d);self.assertEqual((self.row()['active'],self.row()['onboarding_state'],self.row()['validation_code']),(0,'blocked','runtime_isolation_changed'))
 def test_snapshot_failure_is_fail_closed_before_activation(self):
  self.add();d=self.deps();base_run=d.runner
  def fail(argv,timeout=0):
   if argv[:3]==['docker','ps','-a']:return 1,'daemon unavailable'
   return base_run(argv,timeout)
  d=Dependencies(d.generate,d.static_validate,d.collect_runtime,fail,d.activate,d.cleanup);reconcile_once(self.db,self.base,1000,d);self.assertEqual((self.row()['active'],self.row()['onboarding_state'],self.row()['validation_code']),(0,'blocked','isolation_snapshot_failed'));self.assertEqual(self.activations,[])
 def test_unrelated_container_change_blocks_activation(self):
  self.add();d=self.deps();seen=[0]
  def run(argv,timeout=0):
   self.calls.append(argv);joined=' '.join(argv)
   if argv[:2]==['docker','inspect'] and argv[-1]=='vpn-new-one':return 1,'not found'
   if argv[:3]==['docker','ps','-a']:return 0,'vpn-other'
   if argv[:2]==['docker','inspect'] and argv[-1]=='vpn-other':seen[0]+=1;return 0,'other-id|'+str(seen[0]-1)
   return 0,''
  d=Dependencies(d.generate,d.static_validate,d.collect_runtime,run,d.activate,d.cleanup);reconcile_once(self.db,self.base,1000,d);self.assertEqual((self.row()['active'],self.row()['validation_code']),(0,'runtime_isolation_changed'))
 def test_not_due_and_existing_active_rows_are_ignored(self):
  self.add('later',state='offline',code='peer_no_response',due=2000);self.add('active-one',state='online',code='online',active=1);self.assertEqual(reconcile_once(self.db,self.base,1000,self.deps()),0);self.assertEqual(self.generated,[])
if __name__=='__main__':unittest.main()
