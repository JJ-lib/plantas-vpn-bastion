import os
import tempfile,unittest
from unittest import mock
from pathlib import Path
from vpn_runtime import runtime_image
import vpn_validation as validation
from vpn_validation import ValidationEvidence,ValidationResult,classify_evidence,collect_runtime_evidence,static_validation_specs,target_probe_spec,run_static_validation,_xfrm_covers_target,_counter_for_reqids,_route_uses_interface
class ValidationTests(unittest.TestCase):
 def test_xfrm_counter_parses_real_iproute2_bytes_suffix(self):
  text='src 192.0.2.1 dst 192.0.2.2\n proto esp spi 0x1 reqid 42 mode tunnel\n lifetime-current:\n  123(bytes), 1(packets)\n'
  self.assertEqual(_counter_for_reqids(text,{42}),123)
 def ev(self,**changes):
  base=dict(container_running=True,daemon_running=True,ike_established=True,child_installed=True,routes_ok=True,xfrm_ok=True,target_ok=True,peer_replied=True,auth_failed=False,proposal_failed=False)
  base.update(changes);return ValidationEvidence(**base)
 def test_established_without_child_is_not_online(self):
  r=classify_evidence('ipsec',self.ev(child_installed=False,xfrm_ok=False,target_ok=False));self.assertNotEqual(r.state,'online');self.assertEqual(r.code,'child_sa_missing')
 def test_target_failure_is_distinct_after_control_and_data_plane(self):
  r=classify_evidence('ipsec',self.ev(target_ok=False));self.assertEqual((r.state,r.stage,r.code,r.retryable),('installed','target','target_unreachable',True))
 def test_all_gates_are_required_for_online(self):
  self.assertEqual(classify_evidence('ipsec',self.ev()).state,'online')
 def test_peer_no_response_auth_and_proposal_are_distinct(self):
  self.assertEqual(classify_evidence('ipsec',self.ev(ike_established=False,child_installed=False,routes_ok=False,xfrm_ok=False,target_ok=False,peer_replied=False)).code,'peer_no_response')
  auth=classify_evidence('ipsec',self.ev(ike_established=False,child_installed=False,routes_ok=False,xfrm_ok=False,target_ok=False,auth_failed=True));self.assertEqual((auth.code,auth.retryable),('auth_failed',False))
  prop=classify_evidence('ipsec',self.ev(ike_established=False,child_installed=False,routes_ok=False,xfrm_ok=False,target_ok=False,proposal_failed=True));self.assertEqual((prop.code,prop.retryable),('proposal_failed',False))
 def test_public_results_never_include_raw_diagnostics(self):
  r=classify_evidence('ipsec',self.ev(auth_failed=True),raw_diagnostics='PSK=do-not-leak password=do-not-leak EncX secret');self.assertNotIn('do-not-leak',repr(r));self.assertNotIn('EncX',repr(r))
 def test_target_probe_accepts_only_literal_ipv4_and_port(self):
  spec=target_probe_spec('safe-slug','192.0.2.40',443);self.assertEqual(spec[:3],['docker','exec','vpn-safe-slug']);self.assertIn('/dev/tcp/192.0.2.40/443',spec[-1])
  for bad in [('192.0.2.1;id',443),('2001:db8::1',443),('192.0.2.1',0)]:
   with self.assertRaises(ValueError):target_probe_spec('safe-slug',*bad)
 def test_ssrf_targets_are_rejected_before_docker_exec(self):
  for ip in ('127.0.0.1','169.254.169.254','100.64.0.1','100.64.0.2','100.64.0.3'):
   with self.assertRaises(ValueError):target_probe_spec('safe',ip,443)
 def test_pptp_accepts_only_exact_parse_completion_marker(self):
  v={'slug':'x','vpn_type':'pptp','ipsec_engine':''}
  def good(argv,timeout=20):
   cmd=' '.join(argv)
   if 'pppd dryrun' in cmd:return 2,'pppd: no device specified and stdin is not a tty'
   return 0,''
  with mock.patch('vpn_validation._validate_generated_files',return_value=True):self.assertEqual(run_static_validation(v,tempfile.mkdtemp(),good).code,'local_validated')
 def test_static_specs_use_exact_immutable_image_and_no_build(self):
  with tempfile.TemporaryDirectory() as td:
   base=Path(td);(base/'sites/safe').mkdir(parents=True);(base/'configs/safe').mkdir(parents=True);(base/'docker-compose.yml').write_text('services: {}');(base/'sites/safe/compose.yml').write_text('services:\n  vpn-safe:\n    image: sha256:4485a68977905a75386d770aa1f473d316b5b2ae808caf03e7df09034ec8e6c6\n    container_name: vpn-safe\n    labels:\n      plantas.vpn.slug: \"safe\"');(base/'configs/safe/ipsec.conf').write_text('config setup\nconn plant-ipsec\n');(base/'configs/safe/ipsec.secrets').write_text('synthetic : PSK \"test-only\"');(base/'configs/safe/ipsec.secrets').chmod(0o600)
   vpn={'slug':'safe','vpn_type':'ipsec','ipsec_engine':'strongswan'};specs=static_validation_specs(vpn,base);flat=' '.join(' '.join(x) for x in specs);self.assertIn('sha256:4485a68977905a75386d770aa1f473d316b5b2ae808caf03e7df09034ec8e6c6',flat);self.assertNotIn(':latest',flat);self.assertNotIn('--build',flat);self.assertIn('--pull never',flat);self.assertIn('--network none',flat);self.assertNotIn('--cap-add',flat);self.assertIn('--read-only',flat);self.assertIn('--tmpfs /run',flat)
 def test_static_runner_accepts_healthy_strongswan_timeout_and_blocks_syntax_error(self):
  with tempfile.TemporaryDirectory() as td:
   base=Path(td);(base/'sites/safe').mkdir(parents=True);(base/'configs/safe').mkdir(parents=True);(base/'docker-compose.yml').write_text('services: {}');(base/'sites/safe/compose.yml').write_text('services:\n  vpn-safe:\n    image: sha256:4485a68977905a75386d770aa1f473d316b5b2ae808caf03e7df09034ec8e6c6\n    container_name: vpn-safe\n    labels:\n      plantas.vpn.slug: \"safe\"');(base/'configs/safe/ipsec.conf').write_text('config setup\nconn plant-ipsec\n');(base/'configs/safe/ipsec.secrets').write_text('synthetic : PSK \"test-only\"');(base/'configs/safe/ipsec.secrets').chmod(0o600)
   vpn={'slug':'safe','vpn_type':'ipsec','ipsec_engine':'strongswan'}
   def good_runner(argv,timeout=0):return (0,"starter loaded plant-ipsec; charon") if '/usr/lib/ipsec/starter' in ' '.join(argv) else (0,'valid')
   good=run_static_validation(vpn,base,good_runner);self.assertEqual(good.code,'local_validated')
   no_marker=run_static_validation(vpn,base,lambda argv,timeout=0:(0,"starter charon without named connection") if '/usr/lib/ipsec/starter' in ' '.join(argv) else (0,'valid'));self.assertEqual(no_marker.code,'config_invalid')
   bad=run_static_validation(vpn,base,lambda argv,timeout=0:(1,'syntax error') if '/usr/lib/ipsec/starter' in ' '.join(argv) else (0,'valid'));self.assertEqual((bad.state,bad.code),('draft','config_invalid'))
 def test_ssl_preflight_consumes_config_and_rejects_parser_errors(self):
  with tempfile.TemporaryDirectory() as td:
   base=Path(td);(base/'configs/safe').mkdir(parents=True);(base/'sites/safe').mkdir(parents=True);(base/'docker-compose.yml').write_text('services: {}');(base/'configs/safe/openfortivpn.conf').write_text('host = 192.0.2.10\nport = 443\nusername = synthetic\npassword = synthetic\n');os.chmod(base/'configs/safe/openfortivpn.conf',0o600);(base/'sites/safe/compose.yml').write_text('container_name: vpn-safe\n    image: '+runtime_image('ssl')+'\n      plantas.vpn.slug: "safe"\n')
   vpn={'slug':'safe','vpn_type':'ssl','ipsec_engine':''};seen=[]
   def ok(argv,timeout=0):
    joined=' '.join(argv);seen.append(joined);return (1,'could not connect to gateway') if 'openfortivpn -c ' in joined else (0,'ok')
   self.assertEqual(run_static_validation(vpn,base,ok).code,'local_validated');self.assertTrue(any('openfortivpn -c ' in x and '--help' not in x for x in seen))
   def bad(argv,timeout=0):return (1,'error parsing configuration: unknown option') if 'openfortivpn -c ' in ' '.join(argv) else (0,'ok')
   self.assertEqual(run_static_validation(vpn,base,bad).code,'config_invalid')
 def test_collect_runtime_evidence_uses_read_only_commands_and_classifies_markers(self):
  calls=[];counter=[10]
  def run(argv,timeout=0):
   calls.append(argv);joined=' '.join(argv)
   if '{{json .NetworkSettings.Networks}}' in joined:return 0,'{}'
   if 'inspect' in argv:return 0,'abc123 0 true healthy'
   if 'statusall' in joined:return 0,"plant-ipsec[1]: ESTABLISHED remote 192.0.2.2\nplant-ipsec{1}: INSTALLED, TUNNEL, reqid 42 remote 192.0.2.2"
   if joined.endswith('ip xfrm policy'):return 0,'src 192.0.2.0/24 dst 192.0.2.0/24 dir out tmpl src 192.0.2.1 dst 192.0.2.2 proto esp mode tunnel reqid 42\nsrc 192.0.2.0/24 dst 192.0.2.0/24 dir in tmpl src 192.0.2.2 dst 192.0.2.1 proto esp mode tunnel reqid 42'
   if joined.endswith('ip -s xfrm state'):counter[0]+=10;return 0,'src 192.0.2.1 dst 192.0.2.2 reqid 42 bytes '+str(counter[0])+'\nsrc 192.0.2.2 dst 192.0.2.1 reqid 42 bytes '+str(counter[0])
   if 'ip route get' in joined:return 0,'192.0.2.40 via 192.0.2.1 dev eth0 src 192.0.2.10'
   if '/dev/tcp/' in joined:return 0,''
   if 'logs' in argv:return 0,'IKE negotiation complete'
   return 0,''
  e=collect_runtime_evidence({'slug':'safe','vpn_type':'ipsec','ipsec_engine':'strongswan','validation_target_ip':'192.0.2.40','validation_target_port':443,'host':'192.0.2.2','remote_subnets_json':'[\"192.0.2.0/24\"]'},run);self.assertEqual(classify_evidence('ipsec',e).state,'online');flat=' '.join(' '.join(x) for x in calls);self.assertNotIn(' compose up ',flat);self.assertNotIn(' restart ',flat);self.assertNotIn(' rm ',flat)
 def test_unrelated_xfrm_and_plain_route_do_not_satisfy_gate(self):
  unrelated='src 192.0.2.0/24 dst 203.0.113.0/24 dir out tmpl src 1.1.1.1 dst 2.2.2.2 proto esp mode tunnel reqid 42\nsrc 203.0.113.0/24 dst 192.0.2.0/24 dir in tmpl src 2.2.2.2 dst 1.1.1.1 proto esp mode tunnel reqid 42'
  self.assertFalse(_xfrm_covers_target(unrelated,'192.0.2.40'));self.assertFalse(_route_uses_interface('192.0.2.40 via 192.0.2.1 dev eth0','tun0'));self.assertTrue(_route_uses_interface('192.0.2.40 dev tun0','tun0'))
 def _correlated_runner(self,status,route='192.0.2.40 via 198.51.100.1 dev eth0 src 192.0.2.10',peer='192.0.2.2',child_reqid=42,policy_reqid=42,bidirectional=True,addr='2: eth0    inet 192.0.2.10/32 scope global eth0',tcp_rc=0):
  calls=[];rounds=[100,120]
  policy=f'src 192.0.2.10/32 dst 192.0.2.0/24 dir out tmpl src 198.51.100.2 dst {peer} proto esp mode tunnel reqid {policy_reqid}\nsrc 192.0.2.0/24 dst 192.0.2.10/32 dir in tmpl src {peer} dst 198.51.100.2 proto esp mode tunnel reqid {policy_reqid}'
  def run(argv,timeout=0):
   calls.append(argv);joined=' '.join(argv)
   if '{{json .NetworkSettings.Networks}}' in joined:return 0,'{}'
   if 'inspect --format' in joined:return 0,'abc123 0 true healthy'
   if 'statusall' in joined or 'ipsec status;' in joined:return 0,status
   if 'getent ahostsv4' in joined:return 0,peer+' STREAM vpn.example\n'
   if joined.endswith('ip xfrm policy'):return 0,policy
   if joined.endswith('ip -4 addr show'):return 0,addr
   if joined.endswith('ip -s xfrm state'):
    n=rounds.pop(0) if rounds else 120;incoming=n if bidirectional else 100
    return 0,f'src 198.51.100.2 dst {peer}\n proto esp reqid {policy_reqid} mode tunnel\n {n}(bytes)\nsrc {peer} dst 198.51.100.2\n proto esp reqid {policy_reqid} mode tunnel\n {incoming}(bytes)'
   if 'ip route get' in joined:return 0,route
   if '/dev/tcp/' in joined:return tcp_rc,''
   if 'logs' in argv:return 0,'received packet'
   return 0,''
  return run,calls
 def test_ipsec_rejects_child_reqid_peer_source_or_one_way_counter_mismatch(self):
  base={'slug':'safe','vpn_type':'ipsec','ipsec_engine':'strongswan','validation_target_ip':'192.0.2.40','validation_target_port':443,'host':'192.0.2.2','remote_subnets_json':'["192.0.2.0/24"]'}
  cases=[
   ("plant-ipsec[1]: ESTABLISHED remote 192.0.2.99\nplant-ipsec{1}: INSTALLED, reqid 42 remote 192.0.2.99",{},False),
   ("plant-ipsec[1]: ESTABLISHED remote 192.0.2.2\nplant-ipsec{1}: INSTALLED, reqid 9 remote 192.0.2.2",{},False),
   ("plant-ipsec[1]: ESTABLISHED remote 192.0.2.2\nplant-ipsec{1}: INSTALLED, reqid 42 remote 192.0.2.2",{'route':'192.0.2.40 dev eth0 src 198.51.100.2'},False),
   ("plant-ipsec[1]: ESTABLISHED remote 192.0.2.2\nplant-ipsec{1}: INSTALLED, reqid 42 remote 192.0.2.2",{'bidirectional':False},False)]
  for status,kw,_ in cases:
   run,_=self._correlated_runner(status,**kw);self.assertNotEqual(classify_evidence(base,collect_runtime_evidence(base,run)).state,'online')
 def test_ipsec_bidirectional_reject_is_reported_as_closed_tcp_port(self):
  v={'slug':'safe','vpn_type':'ipsec','ipsec_engine':'strongswan','validation_target_ip':'192.0.2.40','validation_target_port':443,'host':'vpn.example','remote_subnets_json':'["192.0.2.0/24"]'};status='plant-ipsec[1]: ESTABLISHED remote 192.0.2.2\nplant-ipsec{1}:  INSTALLED, TUNNEL, reqid 42 remote 192.0.2.2';run,_=self._correlated_runner(status,tcp_rc=1);e=collect_runtime_evidence(v,run);r=classify_evidence(v,e);self.assertTrue(e.traffic_out);self.assertTrue(e.traffic_in);self.assertFalse(e.target_tcp_ok);self.assertEqual((r.state,r.stage,r.code,r.retryable),('installed','target','target_tcp_unreachable',True));self.assertIn('puerto TCP',r.public_message)
 def test_ipsec_without_target_validates_control_plane_without_tcp_probe(self):
  v={'slug':'safe','vpn_type':'ipsec','ipsec_engine':'strongswan','validation_target_ip':'','validation_target_port':None,'host':'vpn.example','remote_subnets_json':'["198.51.100.0/24"]'};status='plant-ipsec[1]: ESTABLISHED remote 192.0.2.2\nplant-ipsec{1}:  INSTALLED, TUNNEL, reqid 42 remote 192.0.2.2';run,calls=self._correlated_runner(status);e=collect_runtime_evidence(v,run);r=classify_evidence(v,e);self.assertEqual((r.state,r.stage,r.code),('online','tunnel','online'));flat=' '.join(' '.join(x) for x in calls);self.assertNotIn('/dev/tcp/',flat);self.assertNotIn('ip route get',flat);self.assertNotIn('ip -s xfrm state',flat)
 def test_ssl_without_target_validates_ppp_interface_and_route_without_tcp_probe(self):
  calls=[]
  def run(argv,timeout=0):
   calls.append(argv);joined=' '.join(argv)
   if '{{json .NetworkSettings.Networks}}' in joined:return 0,'{}'
   if 'inspect --format' in joined:return 0,'abc123 0 true healthy'
   if 'ip link show ppp0' in joined:return 0,'7: ppp0: <POINTOPOINT,UP>'
   if 'ip -4 addr show dev ppp0' in joined:return 0,'inet 192.0.2.10/32 scope global ppp0'
   if 'ip -4 route show dev ppp0' in joined:return 0,'192.0.2.0/24 dev ppp0'
   if 'logs' in argv:return 0,'tunnel is up and running'
   return 0,''
  v={'slug':'safe','vpn_type':'ssl','ipsec_engine':'','validation_target_ip':'','validation_target_port':None,'remote_subnets_json':'[]'};e=collect_runtime_evidence(v,run);self.assertEqual((classify_evidence(v,e).state,classify_evidence(v,e).stage),('online','tunnel'));flat=' '.join(' '.join(x) for x in calls);self.assertNotIn('/dev/tcp/',flat);self.assertNotIn('ip -s link',flat)
 def test_ipsec_accepts_only_fully_correlated_bidirectional_probe(self):
  v={'slug':'safe','vpn_type':'ipsec','ipsec_engine':'strongswan','validation_target_ip':'192.0.2.40','validation_target_port':443,'host':'vpn.example','remote_subnets_json':'["192.0.2.0/24"]'};status='plant-ipsec[1]: ESTABLISHED remote 192.0.2.2\nplant-ipsec{1}: INSTALLED, TUNNEL, reqid 42 remote 192.0.2.2';run,_=self._correlated_runner(status);self.assertEqual(classify_evidence(v,collect_runtime_evidence(v,run)).state,'online')
 def test_modeconfig_requires_route_source_owned_as_local_vip(self):
  v={'slug':'safe','vpn_type':'ipsec','ipsec_engine':'strongswan','modecfg':'pull','validation_target_ip':'192.0.2.40','validation_target_port':443,'host':'192.0.2.2','remote_subnets_json':'["192.0.2.0/24"]'};status='plant-ipsec[1]: ESTABLISHED remote 192.0.2.2\nplant-ipsec{1}: INSTALLED, TUNNEL, reqid 42 remote 192.0.2.2';run,_=self._correlated_runner(status,addr='2: eth0    inet 198.51.100.2/16 scope global eth0');self.assertEqual(classify_evidence(v,collect_runtime_evidence(v,run)).code,'vip_missing')
 def test_libreswan_normal_child_markers_are_recognized(self):
  v={'slug':'safe','vpn_type':'ipsec','ipsec_engine':'libreswan','validation_target_ip':'192.0.2.40','validation_target_port':443,'host':'192.0.2.2','remote_subnets_json':'["192.0.2.0/24"]'};status='000 "plant-ipsec": 198.51.100.2---192.0.2.2 STATE_MAIN_I4 (ISAKMP SA established)\n006 #2: "plant-ipsec":500 STATE_QUICK_I2 (IPsec SA established)\n006 #2: "plant-ipsec", type=ESP, inBytes=10, outBytes=10';run,_=self._correlated_runner(status);self.assertEqual(classify_evidence(v,collect_runtime_evidence(v,run)).state,'online')
 def test_dynamic_container_network_blocks_probe_before_tcp(self):
  vpn={'slug':'safe','vpn_type':'ipsec','ipsec_engine':'strongswan','validation_target_ip':'198.51.100.40','validation_target_port':443,'host':'192.0.2.2','remote_subnets_json':'["0.0.0.0/0"]'};status='plant-ipsec[1]: ESTABLISHED remote 192.0.2.2\nplant-ipsec{1}: INSTALLED, TUNNEL, reqid 42 remote 192.0.2.2';base,calls=self._correlated_runner(status)
  def run(argv,timeout=0):
   joined=' '.join(argv)
   if '{{json .NetworkSettings.Networks}}' in joined:return 0,'{"bastion":{"IPAddress":"198.51.100.2","IPPrefixLen":24,"Gateway":"198.51.100.1"}}'
   return base(argv,timeout)
  e=collect_runtime_evidence(vpn,run);self.assertFalse(e.target_ok);self.assertFalse(any('python3 -c' in ' '.join(x) for x in calls))
 def test_additional_bridge_and_control_targets_are_rejected(self):
  for ip in ('100.64.0.1','100.64.0.2','100.64.0.3','100.64.0.4'):
   with self.assertRaises(ValueError):target_probe_spec('safe',ip,443)


class LinkCounterFormatTests(unittest.TestCase):
 def test_counter_total_parses_real_ip_s_link_rx_tx_blocks(self):
  text='''2: ppp0: <POINTOPOINT,UP> mtu 1350\n    RX: bytes  packets  errors  dropped missed mcast\n    1234       8        0       0       0      0\n    TX: bytes  packets  errors  dropped carrier collsns\n    5678       9        0       0       0       0'''
  self.assertEqual(6912,validation._counter_total(text))

if __name__=='__main__':unittest.main()
