import json,os,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];TMP=tempfile.TemporaryDirectory();os.environ['PANEL_DATA_DIR']=TMP.name;os.environ['PANEL_DB']=str(Path(TMP.name)/'panel.db');os.environ['PROJECT_DIR']=str(Path(TMP.name)/'project');os.environ['PANEL_BOOTSTRAP_ADMIN_PASSWORD']='synthetic-bootstrap-only-123';sys.path.insert(0,str(ROOT/'panel-app'))
from vpn_runtime import VPN_RUNTIME_IMAGES,expand_ike_proposals,proposal_rows,remote_subnets,runtime_image
import app as panel
DH={'14':'modp2048','20':'ecp384'}
def base():
 return {'plant':'Synthetic','slug':'new-generator','host':'192.0.2.10','port':'500','username':'user','password_enc':panel.enc('credential'),'psk_enc':panel.enc('psk'),'trusted_cert_enc':'','vpn_type':'ipsec','ipsec_engine':'strongswan','ike_version':'ikev1','auth_mode':'psk-xauth','aggressive':1,'phase1_enc':'aes256','phase1_auth':'sha512','dh_group':'14','phase1_enc2':'','phase1_auth2':'','dh_groups':'14,20','phase1_lifetime':'86400','dpd':1,'nat_traversal':1,'phase2_enc':'aes256','phase2_auth':'sha512','phase2_enc2':'','phase2_auth2':'','phase2_lifetime':'43200','pfs':1,'pfs_group':'20','local_id':'','remote_id':'','modecfg':'pull','remote_subnet':'0.0.0.0/0','phase1_proposals_json':json.dumps([{'encryption':'aes256','integrity':'sha512'},{'encryption':'aes256','integrity':'sha256'}]),'phase2_proposals_json':json.dumps([{'encryption':'aes256','integrity':'sha512'},{'encryption':'aes256','integrity':'sha256'}]),'remote_subnets_json':json.dumps(['198.51.0.0/16','192.0.0.0/16']),'openvpn_profile_enc':'','openvpn_key_pass_enc':'','openvpn_requires_auth':0,'openvpn_requires_key_pass':0,'openvpn_routes':''}
class GeneratorTests(unittest.TestCase):
 def setUp(self):Path(os.environ['PROJECT_DIR'],'configs/new-generator').mkdir(parents=True,exist_ok=True);Path(os.environ['PROJECT_DIR'],'sites/new-generator').mkdir(parents=True,exist_ok=True)
 def test_runtime_images_are_immutable(self):
  self.assertEqual(set(VPN_RUNTIME_IMAGES),{'ssl','openvpn','pptp','strongswan','libreswan'});self.assertTrue(all(':latest' not in x and '@sha256:' not in x for x in VPN_RUNTIME_IMAGES.values()))
 def test_expands_complete_suites_by_each_selected_dh(self):
  rows=[{'encryption':'aes256','integrity':'sha512'},{'encryption':'aes256','integrity':'sha256'}]
  self.assertEqual(expand_ike_proposals(rows,['14','20'],DH),['aes256-sha512-modp2048','aes256-sha512-ecp384','aes256-sha256-modp2048','aes256-sha256-ecp384'])
 def test_json_rows_and_subnets_override_legacy_columns(self):
  v=base();self.assertEqual(len(proposal_rows(v,1)),2);self.assertEqual(remote_subnets(v),['198.51.0.0/16','192.0.0.0/16'])
 def test_ikev1_strongswan_preserves_multiple_proposals_dh_and_independent_pfs(self):
  v=base();panel.gen_ikev1_xauth_strongswan(v,'new-generator');root=Path(os.environ['PROJECT_DIR']);conf=(root/'configs/new-generator/ipsec.conf').read_text();compose=(root/'sites/new-generator/compose.yml').read_text()
  self.assertIn('ike=aes256-sha512-modp2048,aes256-sha512-ecp384,aes256-sha256-modp2048,aes256-sha256-ecp384!',conf);self.assertIn('esp=aes256-sha512-ecp384,aes256-sha256-ecp384!',conf);self.assertIn('rightsubnet=198.51.0.0/16,192.0.0.0/16',conf);self.assertNotIn('build:',compose);self.assertNotIn(':latest',compose);self.assertIn(VPN_RUNTIME_IMAGES['strongswan'],compose)
 def test_ikev2_has_reauth_no_and_immutable_image(self):
  v=base();v.update(ike_version='ikev2',auth_mode='eap-mschapv2-psk');panel.gen_ikev2_eap(v,'new-generator');root=Path(os.environ['PROJECT_DIR']);conf=(root/'configs/new-generator/ipsec.conf').read_text();compose=(root/'sites/new-generator/compose.yml').read_text();self.assertIn('reauth=no',conf);self.assertIn(VPN_RUNTIME_IMAGES['strongswan'],compose);self.assertNotIn('build:',compose)
 def test_empty_draft_haproxy_has_private_health_listener(self):
  panel.ensure_haproxy('new-generator','Synthetic');text=Path(os.environ['PROJECT_DIR'],'configs/new-generator/haproxy.cfg').read_text();self.assertIn('bind 127.0.0.1:8404',text);self.assertIn('http-request return status 200',text);self.assertNotIn('bind 0.0.0.0:8404',text)
 def test_access_and_ssl_compose_are_immutable(self):
  source=(ROOT/'panel-app/app.py').read_text()
  for mutable in ('bastion-vpn-proxy:latest','bastion-access-vpn-proxy:latest','bastion-ipsec-proxy:latest','bastion-libreswan-proxy:latest'):self.assertNotIn(mutable,source)
if __name__=='__main__':unittest.main()
