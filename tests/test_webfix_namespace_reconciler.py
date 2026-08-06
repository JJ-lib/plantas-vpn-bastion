import fcntl,os,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
DEFAULT_SOURCE=HERE if (HERE/'vpn_reconciler.py').is_file() else (HERE/'candidate/panel-app' if (HERE/'candidate/panel-app').is_dir() else HERE.parent/'panel-app')
SOURCE=Path(os.environ.get('VPN_RECONCILER_SOURCE_UNDER_TEST',DEFAULT_SOURCE)).resolve()
sys.path.insert(0,str(SOURCE))
from vpn_reconciler import reconcile_webfix_namespaces,webfix_repair_spec

class FakeRunner:
 def __init__(self,**kw):
  self.commands=[];self.names=kw.get('names',['webfix-demo']);self.project=kw.get('project','bastion-vpn');self.labels_ok=kw.get('labels_ok',True);self.vpn_running=kw.get('vpn_running',True);self.web_running=kw.get('web_running',True);self.vpn_ns=kw.get('vpn_ns','net:[2]');self.web_ns=kw.get('web_ns','net:[2]');self.vpn_id=kw.get('vpn_id','a'*64);self.web_id='e'*64;self.vpn_restart=3;self.web_restart=0;self.vpn_network_mode='bridge';self.web_network_mode=kw.get('web_network_mode','container:'+self.vpn_id);self.config_rc=kw.get('config_rc',0);self.up_rc=kw.get('up_rc',0);self.post_sync=kw.get('post_sync',True);self.change_vpn=kw.get('change_vpn',False);self.inspect_fail=set(kw.get('inspect_fail',()));self.raise_on=set(kw.get('raise_on',()));self.netns_fail=set(kw.get('netns_fail',()));self.discovery_rc=kw.get('discovery_rc',0);self.race_post=kw.get('race_post',False);self.race_late=kw.get('race_late',False);self.race_pre=kw.get('race_pre',False);self.race_final_web=kw.get('race_final_web',False);self.vpn_mode_after_up=kw.get('vpn_mode_after_up',False);self.foreign_target=kw.get('foreign_target','');self.id_list_rc=kw.get('id_list_rc',0);self.id_list_malformed=kw.get('id_list_malformed',False);self.change_web_id=kw.get('change_web_id',True);self.did_up=False;self.race_fired=False;self.post_vpn_execs=0;self.pre_vpn_execs=0;self.post_web_inspects=0
 def __call__(self,argv,timeout=0):
  self.commands.append(list(argv))
  if argv[:3]==['docker','ps','-a']:
   if '--no-trunc' in argv:
    if self.id_list_rc:return self.id_list_rc,''
    ids=[self.vpn_id,self.web_id]+([self.foreign_target] if self.foreign_target else []);return 0,('malformed\n' if self.id_list_malformed else '\n'.join(ids)+'\n')
   return self.discovery_rc,('\n'.join(self.names)+'\n' if self.discovery_rc==0 else '')
  if argv[:2]==['docker','inspect']:
   name=argv[-1]
   if name in self.raise_on:raise RuntimeError('synthetic inspect exception')
   if name in self.inspect_fail:return 1,''
   if self.foreign_target and name==self.foreign_target:return 0,f"true|bastion-vpn|vpn-foreign|{self.foreign_target}|0|bridge"
   if name.startswith('vpn-'):
    return 0,f"{str(self.vpn_running).lower()}|bastion-vpn|{name}|{self.vpn_id}|{self.vpn_restart}|{'host' if self.vpn_mode_after_up and self.did_up else self.vpn_network_mode}"
   if name.startswith('webfix-'):
    project=self.project;service=name if self.labels_ok else 'webfix-other';result=(0,f"{str(self.web_running).lower()}|{project}|{service}|{self.web_id}|{self.web_restart}|{self.web_network_mode}")
    if self.did_up and self.race_final_web:
     self.post_web_inspects+=1
     if self.post_web_inspects==2:self.vpn_ns='net:[9]';self.vpn_id='9'*64;self.vpn_restart+=1
    return result
   return 1,'not found'
  if argv[:2]==['docker','exec']:
   if argv[2] in self.netns_fail:return 1,''
   if argv[2].startswith('vpn-'):
    value=self.vpn_ns
    if self.race_late and self.did_up:
     self.post_vpn_execs+=1
     if self.post_vpn_execs==2:self.vpn_ns='net:[3]';self.vpn_id='b'*64;self.vpn_restart+=1
    if self.race_pre and not self.did_up:
     self.pre_vpn_execs+=1
     if self.pre_vpn_execs==3:self.vpn_ns='net:[4]';self.vpn_id='d'*64;self.vpn_restart+=1
    return (0,value) if self.vpn_running else (1,'')
   if argv[2].startswith('webfix-'):
    value=self.web_ns
    if self.race_post and self.did_up and not self.race_fired:self.race_fired=True;self.vpn_ns='net:[3]'
    return (0,value) if self.web_running else (1,'')
  if 'config' in argv and '-q' in argv:return self.config_rc,''
  if 'up' in argv:
   if self.up_rc:return self.up_rc,''
   self.did_up=True;self.web_running=True;self.web_id='c'*64 if self.change_web_id else self.web_id;self.web_restart=0;self.web_network_mode='container:'+self.vpn_id
   if self.post_sync:self.web_ns=self.vpn_ns
   if self.change_vpn:self.vpn_restart+=1
   return 0,''
  return 1,'unexpected'

class WebfixNamespaceReconcilerTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.base=Path(self.t.name);(self.base/'sites/demo').mkdir(parents=True);(self.base/'docker-compose.yml').write_text('services: {}\n');(self.base/'sites/demo/compose.yml').write_text('services: {}\n');self.locks=self.base/'locks';self.cooldowns={}
 def tearDown(self):self.t.cleanup()
 def run_once(self,fake,now=1000,clock=None):
  kwargs={'runner':fake,'now':now,'cooldowns':self.cooldowns,'lock_dir':self.locks,'project':'bastion-vpn'}
  if clock is not None:kwargs['clock']=clock
  return reconcile_webfix_namespaces(self.base,**kwargs)
 def up_commands(self,fake):return [x for x in fake.commands if 'up' in x]
 def test_repair_spec_is_sidecar_only_and_forbids_broad_lifecycle_commands(self):
  spec=webfix_repair_spec(self.base,'demo');flat=' '.join(spec);self.assertEqual(spec[-1],'webfix-demo');self.assertIn('up -d --no-deps --force-recreate --pull never --no-build webfix-demo',flat)
  for bad in ('--remove-orphans',' down ',' rm ',' restart '):self.assertNotIn(bad,' '+flat+' ')
  self.assertNotIn('vpn-demo',spec)
 def test_matching_namespace_is_noop(self):
  f=FakeRunner();self.assertEqual(self.run_once(f).get('demo'),'in_sync');self.assertEqual(self.up_commands(f),[])
 def test_mismatch_repairs_only_webfix_and_rechecks_postcondition(self):
  f=FakeRunner(web_ns='net:[1]');self.assertEqual(self.run_once(f).get('demo'),'repaired');self.assertEqual(len(self.up_commands(f)),1);self.assertEqual(f.web_id,'c'*64);self.assertEqual((f.vpn_id,f.vpn_restart),('a'*64,3));self.assertEqual(f.web_ns,f.vpn_ns)
 def test_stopped_sidecar_is_recovered(self):
  f=FakeRunner(web_running=False,web_ns='',web_network_mode='container:'+'f'*64);self.assertEqual(self.run_once(f).get('demo'),'repaired');self.assertEqual(len(self.up_commands(f)),1)
 def test_stopped_sidecar_with_current_target_is_not_mutated(self):
  f=FakeRunner(web_running=False,web_ns='');self.assertEqual(self.run_once(f).get('demo'),'webfix_not_running');self.assertEqual(self.up_commands(f),[])
 def test_invalid_slug_or_ownership_never_mutates(self):
  bad=FakeRunner(names=['webfix-BAD']);self.assertEqual(self.run_once(bad).get('webfix-BAD'),'invalid_slug');self.assertEqual(self.up_commands(bad),[])
  foreign=FakeRunner(project='foreign');self.assertEqual(self.run_once(foreign).get('demo'),'invalid_ownership');self.assertEqual(self.cooldowns['demo'],1300);self.assertEqual(self.up_commands(foreign),[])
 def test_vpn_not_running_never_mutates(self):
  f=FakeRunner(vpn_running=False,web_ns='net:[1]');self.assertEqual(self.run_once(f).get('demo'),'vpn_not_running');self.assertEqual(self.up_commands(f),[])
 def test_busy_slug_lock_skips_without_mutation(self):
  self.locks.mkdir();fd=os.open(self.locks/'demo.lock',os.O_CREAT|os.O_RDWR,0o600);fcntl.flock(fd,fcntl.LOCK_EX)
  try:
   f=FakeRunner(web_ns='net:[1]');self.assertEqual(self.run_once(f).get('demo'),'locked');self.assertEqual(self.up_commands(f),[])
  finally:fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)
 def test_compose_failure_sets_cooldown_and_does_not_recreate(self):
  f=FakeRunner(web_ns='net:[1]',config_rc=1);self.assertEqual(self.run_once(f,1000).get('demo'),'compose_invalid');self.assertEqual(self.cooldowns['demo'],1300);self.assertEqual(self.up_commands(f),[])
  self.assertEqual(self.run_once(f,1100).get('demo'),'cooldown');self.assertEqual(self.up_commands(f),[])
 def test_recreate_or_postcondition_failure_sets_cooldown(self):
  f=FakeRunner(web_ns='net:[1]',up_rc=1);self.assertEqual(self.run_once(f,1000).get('demo'),'repair_failed');self.assertEqual(self.cooldowns['demo'],1300)
  self.cooldowns.clear();g=FakeRunner(web_ns='net:[1]',post_sync=False);self.assertEqual(self.run_once(g,1000).get('demo'),'postcondition_failed');self.assertEqual(self.cooldowns['demo'],1300)
 def test_vpn_change_during_repair_fails_closed(self):
  f=FakeRunner(web_ns='net:[1]',change_vpn=True);self.assertEqual(self.run_once(f).get('demo'),'vpn_changed');self.assertEqual(self.cooldowns['demo'],1300)
 def test_inspection_failure_sets_cooldown(self):
  f=FakeRunner(inspect_fail={'webfix-demo'});self.assertEqual(self.run_once(f).get('demo'),'inspection_failed');self.assertEqual(self.cooldowns['demo'],1300);self.assertEqual(self.up_commands(f),[])
 def test_namespace_inspection_failure_sets_cooldown(self):
  f=FakeRunner(netns_fail={'webfix-demo'});self.assertEqual(self.run_once(f).get('demo'),'namespace_inspection_failed');self.assertEqual(self.cooldowns['demo'],1300);self.assertEqual(self.up_commands(f),[])
 def test_exception_is_isolated_and_later_slug_is_processed(self):
  f=FakeRunner(names=['webfix-a','webfix-b'],raise_on={'webfix-a'});result=self.run_once(f);self.assertEqual(result.get('a'),'cycle_failed');self.assertEqual(result.get('b'),'in_sync');self.assertEqual(self.cooldowns['a'],1300)
 def test_vpn_namespace_change_between_post_reads_fails_closed(self):
  f=FakeRunner(web_ns='net:[1]',race_post=True);self.assertEqual(self.run_once(f).get('demo'),'postcondition_failed');self.assertEqual(self.cooldowns['demo'],1300);self.assertNotEqual(f.vpn_ns,f.web_ns)
 def test_vpn_change_after_last_metadata_before_last_namespace_sample_fails_closed(self):
  f=FakeRunner(web_ns='net:[1]',race_late=True);self.assertEqual(self.run_once(f).get('demo'),'vpn_changed');self.assertEqual(self.cooldowns['demo'],1300);self.assertNotEqual(f.vpn_ns,f.web_ns)
 def test_unstable_premutation_mismatch_fails_closed(self):
  f=FakeRunner(web_ns='net:[1]',race_pre=True);self.assertEqual(self.run_once(f).get('demo'),'vpn_changed');self.assertEqual(self.up_commands(f),[])
 def test_force_recreate_must_change_webfix_id(self):
  f=FakeRunner(web_ns='net:[1]',change_web_id=False);self.assertEqual(self.run_once(f).get('demo'),'postcondition_failed');self.assertEqual(self.cooldowns['demo'],1300)
 def test_main_uses_live_failure_clock(self):
  source=(DEFAULT_SOURCE/'vpn_reconciler.py').read_text();self.assertNotIn('reconcile_webfix_namespaces(base,now=',source)
 def test_stopped_invalid_network_modes_fail_closed(self):
  for mode in ('bridge','none','','container:not-a-container-id'):
   with self.subTest(mode=mode):
    self.cooldowns.clear();f=FakeRunner(web_running=False,web_ns='',web_network_mode=mode);self.assertEqual(self.run_once(f).get('demo'),'invalid_network_mode');self.assertEqual(self.up_commands(f),[])
 def test_stopped_foreign_existing_container_target_fails_closed(self):
  foreign='7'*64;f=FakeRunner(web_running=False,web_ns='',web_network_mode='container:'+foreign,foreign_target=foreign);self.assertEqual(self.run_once(f).get('demo'),'invalid_network_mode');self.assertEqual(self.up_commands(f),[])
 def test_stopped_target_listing_error_fails_closed(self):
  f=FakeRunner(web_running=False,web_ns='',web_network_mode='container:'+'f'*64,id_list_rc=1);self.assertEqual(self.run_once(f).get('demo'),'inspection_failed');self.assertEqual(self.up_commands(f),[])
 def test_stopped_target_malformed_listing_fails_closed(self):
  f=FakeRunner(web_running=False,web_ns='',web_network_mode='container:'+'f'*64,id_list_malformed=True);self.assertEqual(self.run_once(f).get('demo'),'inspection_failed');self.assertEqual(self.up_commands(f),[])
 def test_vpn_restart_during_final_web_inspect_fails_closed(self):
  f=FakeRunner(web_ns='net:[1]',race_final_web=True);self.assertEqual(self.run_once(f).get('demo'),'vpn_changed');self.assertNotEqual(f.vpn_ns,f.web_ns)
 def test_vpn_network_mode_change_is_detected(self):
  f=FakeRunner(web_ns='net:[1]',vpn_mode_after_up=True);self.assertEqual(self.run_once(f).get('demo'),'vpn_changed')
 def test_discovery_failure_has_global_cooldown(self):
  f=FakeRunner(discovery_rc=1);self.assertEqual(self.run_once(f,1000).get('_discovery'),'discovery_failed');self.assertEqual(self.cooldowns['_discovery'],1300);first=len([x for x in f.commands if x[:3]==['docker','ps','-a']]);self.assertEqual(self.run_once(f,1100).get('_discovery'),'cooldown');self.assertEqual(len([x for x in f.commands if x[:3]==['docker','ps','-a']]),first)
 def test_cooldown_starts_at_failure_time_not_cycle_start(self):
  ticks=iter([1000,1045]);f=FakeRunner(web_ns='net:[1]',config_rc=1);self.assertEqual(self.run_once(f,now=None,clock=lambda:next(ticks)).get('demo'),'compose_invalid');self.assertEqual(self.cooldowns['demo'],1345)

if __name__=='__main__':unittest.main()
