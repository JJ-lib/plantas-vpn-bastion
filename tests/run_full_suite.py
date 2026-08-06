from pathlib import Path
import os,re,subprocess,sys,tempfile
ROOT=Path(__file__).resolve().parents[1];excluded={};tests=sorted(p.name for p in (ROOT/'tests').glob('test_*.py') if p.name not in excluded);failed=[];total=0
for name in tests:
 with tempfile.TemporaryDirectory(prefix='vpn-suite-') as td:
  env=os.environ.copy();env['PANEL_APP_UNDER_TEST']=str(ROOT/'panel-app/app.py');env['PYTHONPATH']=str(ROOT/'panel-app')+os.pathsep+env.get('PYTHONPATH','');env['PANEL_DATA_DIR']=td;env['PANEL_DB']=str(Path(td)/'panel.db');env['PROJECT_DIR']=str(ROOT);env['ONBOARDING_LOCK_DIR']=str(Path(td)/'locks');env['PANEL_BOOTSTRAP_ADMIN_PASSWORD']='synthetic-test-bootstrap-password'
  if name!='test_vpn_onboarding_forms.py':env['PANEL_TEST_ALLOW_MISSING_CSRF']='1'
  else:env.pop('PANEL_TEST_ALLOW_MISSING_CSRF',None)
  r=subprocess.run([sys.executable,'-m','unittest','discover','-s',str(ROOT/'tests'),'-p',name],cwd=ROOT,env=env,text=True,capture_output=True)
 text=r.stdout+'\n'+r.stderr;m=re.findall(r'Ran (\d+) tests?',text);total+=int(m[-1]) if m else 0
 print(('PASS ' if r.returncode==0 else 'FAIL ')+name)
 if r.returncode:failed.append(name);print('\n'.join(text.splitlines()[-35:]))
print(f'FILES={len(tests)} TESTS={total} FAILED={len(failed)} EXCLUDED={len(excluded)}')
for name,reason in excluded.items():print(f'EXCLUDED {name}: {reason}')
if failed:print('FAILED_FILES='+','.join(failed));raise SystemExit(1)
