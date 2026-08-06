import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'panel-app'))
from forticlient_import import FortiClientProfileError,MAX_FORTICLIENT_BYTES,parse_endpoint,parse_forticlient_backup
FIXTURE=(ROOT/'tests/fixtures/forticlient-safe-synthetic.xml').read_bytes()
class FortiClientImportTests(unittest.TestCase):
 def test_parses_ssl_ikev1_and_ikev2_without_secrets(self):
  ps=parse_forticlient_backup(FIXTURE);self.assertEqual([p['kind'] for p in ps],['ssl','ipsec','ipsec']);ssl,v1,v2=ps
  self.assertEqual((ssl['host'],ssl['port']),('vpn.example.test','443'));self.assertEqual((v1['ike_version'],v1['exchange_mode']),('ikev1','aggressive'))
  self.assertEqual(v1['phase1_proposals'],[{'encryption':'aes256','integrity':'sha512'}]);self.assertEqual(v1['phase2_proposals'],[{'encryption':'aes256','integrity':'sha512'},{'encryption':'aes256','integrity':'sha256'}])
  self.assertEqual(v2['dh_groups'],['14','20']);self.assertEqual(v2['pfs_group'],'20');self.assertEqual(v2['remote_subnets'],['198.51.0.0/16']);self.assertEqual(v2['source']['version'],'7.4.3')
  flat=repr(ps).lower()
  for x in ('synthetic-ciphertext','encx','preshared_key','password'):self.assertNotIn(x,flat)
 def test_deduplicates_complete_proposals_preserving_order(self):
  xml=FIXTURE.replace(b'<proposal>AES256|SHA512</proposal><proposal>AES256|SHA512</proposal>',b'<proposal>AES256|SHA512</proposal><proposal>AES128|SHA1</proposal><proposal>AES256|SHA512</proposal>',1)
  self.assertEqual(parse_forticlient_backup(xml)[1]['phase1_proposals'],[{'encryption':'aes256','integrity':'sha512'},{'encryption':'aes128','integrity':'sha1'}])
 def test_endpoint_parser_is_strict(self):
  self.assertEqual(parse_endpoint('vpn.example.test:444',443),('vpn.example.test','444'));self.assertEqual(parse_endpoint('[2001:db8::1]:500',500),('2001:db8::1','500'))
  for x in ('','bad host','host:0','host:65536','http://host:443','host:443/path'):
   with self.subTest(x=x),self.assertRaises(FortiClientProfileError):parse_endpoint(x,443)
 def test_rejects_malicious_or_invalid_documents(self):
  samples=[b'<!DOCTYPE x><forticlient_configuration/>',b'<!ENTITY x "y"><forticlient_configuration/>',b'<forticlient_configuration><xi:include/></forticlient_configuration>',b'<forticlient_configuration>\0</forticlient_configuration>',b'<other/>',b'x'*(MAX_FORTICLIENT_BYTES+1)]
  for raw in samples:
   with self.subTest(raw=raw[:20]),self.assertRaises(FortiClientProfileError) as c:parse_forticlient_backup(raw)
   self.assertLess(len(str(c.exception)),180)
 def test_rejects_scripts_sso_certificate_auth_and_unknown_crypto(self):
  muts=[(b'<script/>',b'<script>calc.exe</script>'),(b'<sso_enabled>0</sso_enabled>',b'<sso_enabled>1</sso_enabled>'),(b'<authentication_method>Preshared Key</authentication_method>',b'<authentication_method>Certificate</authentication_method>'),(b'AES256|SHA512',b'BLOWFISH|MD5')]
  for old,new in muts:
   with self.subTest(new=new),self.assertRaises(FortiClientProfileError):parse_forticlient_backup(FIXTURE.replace(old,new,1))
 def test_rejects_profile_count_depth_lifetime_and_ipv6_selector(self):
  c=b'<connection><name>X</name><server>x.test:443</server><sso_enabled>0</sso_enabled><use_external_browser>0</use_external_browser></connection>';xml=b'<forticlient_configuration><version>7.4.3</version><vpn><sslvpn><connections>'+c*65+b'</connections></sslvpn></vpn></forticlient_configuration>'
  bad=[xml,b'<forticlient_configuration>'+b'<x>'*25+b'</x>'*25+b'</forticlient_configuration>',FIXTURE.replace(b'<key_life_type>seconds</key_life_type>',b'<key_life_type>kilobytes</key_life_type>',1),FIXTURE.replace(b'<addr>198.51.100.0</addr><mask>255.255.0.0</mask>',b'<addr>2001:db8::</addr><mask>64</mask>',1)]
  for raw in bad:
   with self.assertRaises(FortiClientProfileError):parse_forticlient_backup(raw)
if __name__=='__main__':unittest.main()
