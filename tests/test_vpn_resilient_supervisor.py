import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUPERVISORS = [ROOT / "images/libreswan-proxy/vpn-supervisor.sh", ROOT / "images/ipsec-proxy/vpn-supervisor.sh"]
FAKE_IPSEC = r"""#!/bin/sh
set -eu
state=${FAKE_STATE_DIR:?}; actions="$state/actions.log"; mkdir -p "$state"; cmd="$*"
case "$cmd" in
  statusall*) case "${FAKE_MODE:-always_down}" in ike_only) echo 'plant-ipsec[1]: ESTABLISHED 100 seconds ago';; online) echo 'plant-ipsec{1}: INSTALLED, TUNNEL';; online_real_spacing) echo 'plant-ipsec{1}:  INSTALLED, TUNNEL';; recover_on_up) test -f "$state/installed" && echo 'plant-ipsec{1}: INSTALLED, TUNNEL' || echo 'plant-ipsec[1]: ESTABLISHED';; esac;;
  status*) exit 0;;
  "whack --trafficstatus"*) case "${FAKE_MODE:-always_down}" in online) echo '006 #1: plant-ipsec, type=ESP';; recover_on_up) test -f "$state/installed" && echo '006 #1: plant-ipsec, type=ESP' || true;; esac;;
  "up "*|"auto --up "*) printf '%s\n' "$cmd" >> "$actions"; if test "${FAKE_MODE:-}" = recover_on_up; then touch "$state/installed"; exit 0; fi; exit 1;;
  "down "*) printf '%s\n' "$cmd" >> "$actions"; rm -f "$state/installed"; exit 0;;
  start*) printf '%s\n' "$cmd" >> "$actions"; exit 0;;
  *) printf '%s\n' "$cmd" >> "$actions"; exit 0;;
esac
"""

class SupervisorTests(unittest.TestCase):
    def run_supervisor(self, script, engine, mode, cycles, threshold=2, haproxy_pid=None, ipsec_pid=None):
        self.assertTrue(script.exists(), f"missing resilient supervisor: {script}")
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); fake=root/'ipsec'; fake.write_text(FAKE_IPSEC); fake.chmod(0o755); state=root/'state'; health=root/'health'
            env=os.environ.copy(); env.update({'VPN_ENGINE':engine,'VPN_CONN_NAME':'plant-ipsec','VPN_HEALTH_FILE':str(health),'VPN_IPSEC_BIN':str(fake),'VPN_CHECK_INTERVAL':'1','VPN_SLEEP_BIN':'true','VPN_FAIL_THRESHOLD':str(threshold),'VPN_BACKOFF_STEPS':'1,2,4','VPN_SUPERVISOR_MAX_CYCLES':str(cycles),'HAPROXY_PID':str(haproxy_pid if haproxy_pid is not None else os.getpid()),'IPSEC_PID':str(ipsec_pid if ipsec_pid is not None else os.getpid()),'FAKE_STATE_DIR':str(state),'FAKE_MODE':mode})
            result=subprocess.run([str(script)],env=env,text=True,capture_output=True,timeout=5)
            actions=(state/'actions.log').read_text().splitlines() if (state/'actions.log').exists() else []
            return result, health.read_text().strip() if health.exists() else None, actions
    def each(self): return SUPERVISORS
    def test_strongswan_ike_only_is_not_online(self):
        for script in self.each():
            with self.subTest(script=script):
                r,h,_=self.run_supervisor(script,'strongswan','ike_only',3); self.assertEqual(r.returncode,0); self.assertIn(h,{'degraded','offline'}); self.assertNotEqual(h,'online')
    def test_single_missing_sample_does_not_recover_or_exit(self):
        for script in self.each():
            with self.subTest(script=script):
                r,h,a=self.run_supervisor(script,'strongswan','always_down',1,2); self.assertEqual(r.returncode,0); self.assertEqual(h,'degraded'); self.assertEqual(a,[])
    def test_strongswan_real_status_spacing_is_online_without_recovery(self):
        for script in self.each():
            with self.subTest(script=script):
                r,h,a=self.run_supervisor(script,'strongswan','online_real_spacing',1,1); self.assertEqual(r.returncode,0); self.assertEqual(h,'online'); self.assertEqual(a,[])
    def test_strongswan_recovers_child_in_place(self):
        for script in self.each():
            with self.subTest(script=script):
                r,h,a=self.run_supervisor(script,'strongswan','recover_on_up',3,1); self.assertEqual(r.returncode,0); self.assertEqual(h,'online'); self.assertEqual(a[0],'up plant-ipsec')
    def test_libreswan_permanent_failure_uses_backoff_without_exit(self):
        for script in self.each():
            with self.subTest(script=script):
                r,h,a=self.run_supervisor(script,'libreswan','always_down',8,1); attempts=[x for x in a if x=='auto --up plant-ipsec']; self.assertEqual(r.returncode,0); self.assertEqual(h,'offline'); self.assertGreaterEqual(len(attempts),1); self.assertLess(len(attempts),8)
    def test_dead_haproxy_is_fatal(self):
        for script in self.each():
            with self.subTest(script=script):
                r,_,_=self.run_supervisor(script,'strongswan','online',1,haproxy_pid=99999999); self.assertEqual(r.returncode,20)
    def test_dead_ipsec_daemon_is_fatal(self):
        for script in self.each():
            with self.subTest(script=script):
                r,_,_=self.run_supervisor(script,'strongswan','online',1,ipsec_pid=99999998); self.assertEqual(r.returncode,21)

    def test_both_engine_supervisors_are_identical(self):
        for script in self.each(): self.assertTrue(script.exists(),f"missing resilient supervisor: {script}")
        self.assertEqual(SUPERVISORS[0].read_bytes(),SUPERVISORS[1].read_bytes())

    def test_entrypoints_delegate_to_supervisor_after_haproxy(self):
        cases=[('libreswan-proxy','libreswan'),('ipsec-proxy','strongswan')]
        for directory,engine in cases:
            with self.subTest(directory=directory):
                name='start-libreswan.sh' if engine=='libreswan' else 'start-ipsec.sh'
                text=(ROOT/'images'/directory/name).read_text()
                self.assertIn(f'export VPN_ENGINE={engine}',text)
                self.assertIn('exec /usr/local/sbin/vpn-supervisor.sh',text)
                self.assertLess(text.index('haproxy -f'),text.index('exec /usr/local/sbin/vpn-supervisor.sh'))
                self.assertNotIn('ERROR: IPsec caído; reiniciando contenedor',text)
                self.assertNotIn('ERROR: túnel caído; reiniciando contenedor',text)
                self.assertRegex(text,r'export[^\n]*\bIPSEC_PID\b')
                if engine=='libreswan':
                    self.assertIn('/usr/libexec/ipsec/pluto --config /etc/ipsec.conf --secretsfile /etc/ipsec.secrets --nofork --stderrlog &',text)
                    self.assertNotIn('\nipsec start\n',text)
                else:
                    self.assertIn('ipsec start --nofork &',text)

    def test_dockerfiles_install_supervisor_and_informational_healthcheck(self):
        for directory in ('libreswan-proxy','ipsec-proxy'):
            with self.subTest(directory=directory):
                text=(ROOT/'images'/directory/'Dockerfile').read_text()
                self.assertIn('COPY vpn-supervisor.sh /usr/local/sbin/vpn-supervisor.sh',text)
                self.assertIn('chmod 0755 /usr/local/sbin/vpn-supervisor.sh',text)
                self.assertIn('HEALTHCHECK',text)
                self.assertIn('grep -qx online /run/vpn-health',text)
                self.assertNotIn('docker restart',text.lower())

if __name__=='__main__': unittest.main()
