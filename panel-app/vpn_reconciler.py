from __future__ import annotations
import json
from dataclasses import dataclass
import argparse,datetime,fcntl,hashlib,os,re,secrets,shutil,sqlite3,subprocess,time
from zoneinfo import ZoneInfo
from pathlib import Path
from vpn_onboarding import ensure_onboarding_schema,set_validation_state
from vpn_validation import ValidationResult,classify_evidence,collect_runtime_evidence,run_static_validation
from vpn_runtime import runtime_image
from plant_paths import plant_artifact_dir
@dataclass(frozen=True)
class Dependencies:
 generate:object
 static_validate:object
 collect_runtime:object
 runner:object
 activate:object
 cleanup:object
 seal_certificate:object=None
 unseal_certificate:object=None
def start_spec(base,slug):
 base=Path(base).resolve();return ['docker','compose','--project-directory',str(base),'-f',str(base/'docker-compose.yml'),'-f',str(plant_artifact_dir(base,slug)/'compose.yml'),'up','-d','--no-deps','--pull','never','--no-build','vpn-'+slug]
def extract_certificate_digests(logs):
 return {m.lower() for m in re.findall(r'(?i)(?:--trusted-cert\s+|trusted-cert\s*=\s*)([a-f0-9]{64})(?![a-f0-9])',str(logs or ''))}
def subprocess_runner(argv,timeout=30):
 try:
  p=subprocess.run(argv,text=True,capture_output=True,timeout=timeout,check=False);return p.returncode,(p.stdout[-40000:]+'\n'+p.stderr[-40000:])
 except subprocess.TimeoutExpired:return 124,''
WEBFIX_SLUG_RE=re.compile(r'[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?')
def _webfix_compose_prefix(base,slug):
 base=Path(base).resolve();return ['docker','compose','--project-directory',str(base),'-f',str(base/'docker-compose.yml'),'-f',str(plant_artifact_dir(base,slug)/'compose.yml')]
def webfix_repair_spec(base,slug):
 if not WEBFIX_SLUG_RE.fullmatch(str(slug or '')):raise ValueError('Slug webfix no válido.')
 return [*_webfix_compose_prefix(base,slug),'up','-d','--no-deps','--force-recreate','--pull','never','--no-build','webfix-'+slug]
def _webfix_meta(runner,name):
 fmt='{{.State.Running}}|{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}|{{.Id}}|{{.RestartCount}}|{{.HostConfig.NetworkMode}}'
 rc,out=runner(['docker','inspect','--format',fmt,name],timeout=10)
 if rc!=0:return None
 parts=out.strip().split('|')
 if len(parts)!=6:return None
 try:restart=int(parts[4])
 except ValueError:return None
 return {'running':parts[0].lower()=='true','project':parts[1],'service':parts[2],'id':parts[3],'restart':restart,'network_mode':parts[5]}
def _webfix_identity(meta):return (meta['id'],meta['restart'],meta['running'],meta['project'],meta['service'],meta['network_mode'])
def _container_presence(runner,container_id):
 rc,out=runner(['docker','ps','-a','--no-trunc','--format','{{.ID}}'],timeout=10)
 if rc!=0:return 'error'
 ids=[x.strip() for x in out.splitlines() if x.strip()]
 if any(not re.fullmatch(r'[0-9a-f]{64}',x) for x in ids):return 'error'
 return 'present' if container_id in ids else 'absent'
def _webfix_netns(runner,name):
 rc,out=runner(['docker','exec',name,'readlink','/proc/1/ns/net'],timeout=10);value=out.strip()
 return value if rc==0 and re.fullmatch(r'net:\[\d+\]',value) else ''
def _webfix_log(slug,status):
 try:stamp=datetime.datetime.now(ZoneInfo('Europe/Madrid')).isoformat(timespec='seconds')
 except Exception:stamp=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
 print(f'{stamp} webfix_reconcile slug={slug} status={status}',flush=True)
def _webfix_failed(cooldowns,slug,now,status):
 cooldowns[slug]=now+300;return status
def _reconcile_webfix_name(base,name,slug,runner,now,failure_now,cooldowns,lock_dir,project):
 if float(cooldowns.get(slug,0) or 0)>now:return 'cooldown'
 vpn_name='vpn-'+slug;web=_webfix_meta(runner,name)
 if web is None:return _webfix_failed(cooldowns,slug,failure_now(),'inspection_failed')
 if web['project']!=project or web['service']!=name:return _webfix_failed(cooldowns,slug,failure_now(),'invalid_ownership')
 vpn=_webfix_meta(runner,vpn_name)
 if vpn is None:return _webfix_failed(cooldowns,slug,failure_now(),'inspection_failed')
 if vpn['project']!=project or vpn['service']!=vpn_name:return _webfix_failed(cooldowns,slug,failure_now(),'invalid_ownership')
 if not vpn['running']:return 'vpn_not_running'
 if web['running']:
  vpn_ns=_webfix_netns(runner,vpn_name);web_ns=_webfix_netns(runner,name)
  if not vpn_ns or not web_ns:return _webfix_failed(cooldowns,slug,failure_now(),'namespace_inspection_failed')
  if vpn_ns==web_ns:cooldowns.pop(slug,None);return 'in_sync'
 lock_dir.mkdir(parents=True,exist_ok=True);fd=None
 try:
  fd=os.open(lock_dir/(slug+'.lock'),os.O_CREAT|os.O_RDWR,0o600)
  try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:return 'locked'
  web=_webfix_meta(runner,name)
  if web is None:return _webfix_failed(cooldowns,slug,failure_now(),'inspection_failed')
  if web['project']!=project or web['service']!=name:return _webfix_failed(cooldowns,slug,failure_now(),'invalid_ownership')
  vpn=_webfix_meta(runner,vpn_name)
  if vpn is None:return _webfix_failed(cooldowns,slug,failure_now(),'inspection_failed')
  if vpn['project']!=project or vpn['service']!=vpn_name:return _webfix_failed(cooldowns,slug,failure_now(),'invalid_ownership')
  if not vpn['running']:return 'vpn_not_running'
  if web['running']:
   vpn_identity=_webfix_identity(vpn);web_identity=_webfix_identity(web)
   vpn_ns_1=_webfix_netns(runner,vpn_name);web_ns_1=_webfix_netns(runner,name);vpn_ns_2=_webfix_netns(runner,vpn_name);web_ns_2=_webfix_netns(runner,name)
   if not all((vpn_ns_1,web_ns_1,vpn_ns_2,web_ns_2)):return _webfix_failed(cooldowns,slug,failure_now(),'namespace_inspection_failed')
   vpn_check=_webfix_meta(runner,vpn_name);web_check=_webfix_meta(runner,name)
   if vpn_check is None or web_check is None:return _webfix_failed(cooldowns,slug,failure_now(),'inspection_failed')
   if _webfix_identity(vpn_check)!=vpn_identity:return _webfix_failed(cooldowns,slug,failure_now(),'vpn_changed')
   if _webfix_identity(web_check)!=web_identity:return _webfix_failed(cooldowns,slug,failure_now(),'postcondition_failed')
   if vpn_ns_1!=vpn_ns_2 or web_ns_1!=web_ns_2:return _webfix_failed(cooldowns,slug,failure_now(),'postcondition_failed')
   if vpn_ns_1==web_ns_1:cooldowns.pop(slug,None);return 'in_sync'
   vpn=vpn_check;web=web_check
  else:
   if web['network_mode']=='container:'+vpn['id']:return 'webfix_not_running'
   target_match=re.fullmatch(r'container:([0-9a-f]{64})',web['network_mode'])
   if not target_match:return _webfix_failed(cooldowns,slug,failure_now(),'invalid_network_mode')
   old_target=target_match.group(1);presence=_container_presence(runner,old_target)
   if presence=='error':return _webfix_failed(cooldowns,slug,failure_now(),'inspection_failed')
   if presence=='present':return _webfix_failed(cooldowns,slug,failure_now(),'invalid_network_mode')
  web_id_before=web['id'];prefix=_webfix_compose_prefix(base,slug);rc,_=runner([*prefix,'config','-q'],timeout=60)
  if rc!=0:return _webfix_failed(cooldowns,slug,failure_now(),'compose_invalid')
  vpn_before=_webfix_identity(vpn);rc,_=runner(webfix_repair_spec(base,slug),timeout=90)
  if rc!=0:return _webfix_failed(cooldowns,slug,failure_now(),'repair_failed')
  vpn_after=_webfix_meta(runner,vpn_name);web_after=_webfix_meta(runner,name)
  if vpn_after is None or web_after is None:return _webfix_failed(cooldowns,slug,failure_now(),'inspection_failed')
  if _webfix_identity(vpn_after)!=vpn_before:return _webfix_failed(cooldowns,slug,failure_now(),'vpn_changed')
  if web_after['id']==web_id_before or not web_after['running'] or web_after['project']!=project or web_after['service']!=name or web_after['network_mode']!='container:'+vpn_before[0]:return _webfix_failed(cooldowns,slug,failure_now(),'postcondition_failed')
  web_before=_webfix_identity(web_after)
  vpn_ns_1=_webfix_netns(runner,vpn_name);web_ns_1=_webfix_netns(runner,name)
  if not vpn_ns_1 or not web_ns_1:return _webfix_failed(cooldowns,slug,failure_now(),'namespace_inspection_failed')
  vpn_ns_2=_webfix_netns(runner,vpn_name);web_ns_2=_webfix_netns(runner,name)
  if not vpn_ns_2 or not web_ns_2:return _webfix_failed(cooldowns,slug,failure_now(),'namespace_inspection_failed')
  vpn_final_1=_webfix_meta(runner,vpn_name);web_final=_webfix_meta(runner,name);vpn_final_2=_webfix_meta(runner,vpn_name)
  if vpn_final_1 is None or web_final is None or vpn_final_2 is None:return _webfix_failed(cooldowns,slug,failure_now(),'inspection_failed')
  if _webfix_identity(vpn_final_1)!=vpn_before or _webfix_identity(vpn_final_2)!=vpn_before:return _webfix_failed(cooldowns,slug,failure_now(),'vpn_changed')
  if _webfix_identity(web_final)!=web_before or web_final['network_mode']!='container:'+vpn_before[0]:return _webfix_failed(cooldowns,slug,failure_now(),'postcondition_failed')
  if len({vpn_ns_1,web_ns_1,vpn_ns_2,web_ns_2})!=1:return _webfix_failed(cooldowns,slug,failure_now(),'postcondition_failed')
  cooldowns.pop(slug,None);return 'repaired'
 finally:
  if fd is not None:
   try:fcntl.flock(fd,fcntl.LOCK_UN)
   except OSError:pass
   os.close(fd)
def reconcile_webfix_namespaces(base,runner=subprocess_runner,now=None,cooldowns=None,lock_dir=None,project='bastion-vpn',clock=time.time):
 base=Path(base).resolve()
 if now is None:
  failure_now=lambda:float(clock());now=failure_now()
 else:
  now=float(now);failure_now=lambda:now
 cooldowns={} if cooldowns is None else cooldowns;lock_dir=Path(lock_dir or os.environ.get('ONBOARDING_LOCK_DIR','/data/vpn-onboarding-locks'));results={}
 if float(cooldowns.get('_discovery',0) or 0)>now:return {'_discovery':'cooldown'}
 try:rc,out=runner(['docker','ps','-a','--format','{{.Names}}'],timeout=10)
 except Exception:cooldowns['_discovery']=failure_now()+300;return {'_discovery':'discovery_failed'}
 if rc!=0:cooldowns['_discovery']=failure_now()+300;return {'_discovery':'discovery_failed'}
 cooldowns.pop('_discovery',None)
 for name in sorted(set(x.strip() for x in out.splitlines() if x.strip().startswith('webfix-'))):
  slug=name[len('webfix-'):]
  if not WEBFIX_SLUG_RE.fullmatch(slug):
   key='invalid:'+name
   if float(cooldowns.get(key,0) or 0)>now:results[name]='cooldown'
   else:cooldowns[key]=failure_now()+300;results[name]='invalid_slug'
   continue
  try:results[slug]=_reconcile_webfix_name(base,name,slug,runner,now,failure_now,cooldowns,lock_dir,project)
  except Exception:
   cooldowns[slug]=failure_now()+300;results[slug]='cycle_failed'
 return results
def default_generate(vpn,base):
 import app as panel
 old=panel.BASE;panel.BASE=str(base);sl=vpn['slug']
 try:
  pd=plant_artifact_dir(base,sl);os.makedirs(Path(base)/f'configs/{sl}',exist_ok=False);pd.parent.mkdir(parents=True,exist_ok=True);pd.mkdir(exist_ok=False);owner=str(vpn.get('generation_owner') or '')
  for d in (Path(base)/f'configs/{sl}',pd):(d/'.onboarding-owner').write_text(owner);os.chmod(d/'.onboarding-owner',0o600)
  with panel.app.app_context():panel.ensure_haproxy(sl,vpn['plant'])
  kind=vpn['vpn_type'] or 'ssl'
  if kind=='ipsec':panel.gen_ipsec(vpn,sl)
  elif kind in {'pptp','openvpn'}:panel.gen_access_vpn(vpn,sl)
  else:panel.gen_ssl(vpn,sl)
  compose=pd/'compose.yml';text=compose.read_text();needle='      plantas.vpn.onboarding: "true"\n'
  if needle not in text:raise RuntimeError('El Compose generado no tiene label de onboarding.')
  text=text.replace(needle,needle+f'      plantas.vpn.owner: "{owner}"\n      plantas.vpn.revision: "{int(vpn.get("onboarding_revision") or 0)}"\n',1);compose.write_text(text)
 finally:panel.BASE=old
def default_activate(conn,vpn,base,runner):
 try:
  equipment=conn.execute("select count(*) from equipment where plant=? and active=1",(vpn['plant'],)).fetchone()[0]
 except sqlite3.OperationalError:equipment=0
 if equipment:return _blocked('activation_publication_required','Existen publicaciones prematuras; active la VPN antes de añadir equipos.')
 rc,info=_container_info(runner,vpn['slug']);parts=info.strip().split('|') if rc==0 else []
 if len(parts)<7 or parts[2]!=vpn['slug'] or parts[3]!=_expected(vpn) or parts[4]!=str(vpn.get('generation_owner') or '') or parts[5]!=str(int(vpn.get('onboarding_revision') or 0)) or parts[6].lower()!='true':return _blocked('activation_runtime_changed','El runtime cambió de owner/revisión/imagen antes de la activación.')
 rc,ports=runner(['docker','inspect','--format','{{json .HostConfig.PortBindings}}',f"vpn-{vpn['slug']}"],timeout=20)
 if rc!=0 or ports.strip() not in {'null','{}',''}:return _blocked('activation_ports_present','El runtime de borrador expone puertos antes de activarse.')
 rc,_=runner(['docker','compose','--project-directory',str(base),'-f',str(Path(base)/'docker-compose.yml'),'-f',str(plant_artifact_dir(base,vpn['slug'])/'compose.yml'),'config','-q'],timeout=60)
 if rc!=0:return _blocked('activation_compose_invalid','El Compose publicado dejó de ser válido.')
 return ValidationResult('active','activation','active','VPN validada y activada sin recrear el runtime.',False)
def default_cleanup(vpn,base,runner):
 sl=vpn['slug'];pd=plant_artifact_dir(base,sl);owner=str(vpn.get('generation_owner') or '');expected=str(vpn.get('runtime_image_ref') or '')
 for name,service in ((f'webfix-{sl}',f'webfix-{sl}'),(f'vpn-{sl}',f'vpn-{sl}')):
  rc,out=runner(['docker','inspect','--format','{{index .Config.Labels "com.docker.compose.service"}}|{{index .Config.Labels "plantas.vpn.slug"}}|{{index .Config.Labels "plantas.vpn.onboarding"}}|{{.Image}}|{{index .Config.Labels "plantas.vpn.owner"}}|{{index .Config.Labels "plantas.vpn.revision"}}',name],timeout=20)
  if rc!=0:continue
  service_got,slug_got,onboarding,image,owner_got,revision_got=(out.strip().split('|')+['','','','','',''])[:6]
  if service_got!=service:raise RuntimeError('Ownership de servicio no válido.')
  if name.startswith('vpn-') and owner and (slug_got!=sl or onboarding!='true' or owner_got!=owner or revision_got!=str(int(vpn.get('onboarding_revision') or 0)) or (expected and image!=expected)):raise RuntimeError('Ownership VPN no válido.')
  rc,_=runner(['docker','rm','-f',name],timeout=60)
  if rc!=0:raise RuntimeError('No se pudo eliminar el contenedor exacto.')
 for d in (Path(base)/f'configs/{sl}',pd):
  if d.exists():
   marker=d/'.onboarding-owner'
   if owner and (not marker.is_file() or marker.read_text()!=owner):raise RuntimeError('Artefactos ajenos al borrador.')
   shutil.rmtree(d)
 caddy=Path(base)/f'caddy/conf.d/{sl}.caddy'
 if caddy.exists():caddy.unlink()
 volume=Path(base).name+'_'+sl+'_web_cache';rc,out=runner(['docker','volume','inspect','--format','{{index .Labels "com.docker.compose.project"}}|{{index .Labels "com.docker.compose.volume"}}',volume],timeout=20)
 if rc==0:
  project,label=(out.strip().split('|')+['',''])[:2]
  if project==Path(base).name and label==sl+'_web_cache':
   rc,_=runner(['docker','volume','rm',volume],timeout=60)
   if rc!=0:raise RuntimeError('No se pudo eliminar el volumen exacto.')
def default_dependencies():return Dependencies(default_generate,run_static_validation,collect_runtime_evidence,subprocess_runner,default_activate,default_cleanup)
def _isolation_blocked(code,message):return ValidationResult('blocked','isolation',code,message,False)
def _blocked(code,message):return ValidationResult('draft','local',code,message,False)
def _manifest(base,slug):
 rows=[]
 for root in (Path(base)/f'configs/{slug}',plant_artifact_dir(base,slug)):
  if not root.is_dir():return ''
  for p in sorted(root.rglob('*')):
   if p.is_file() and p.name!='.onboarding-owner':rows.append(str(p.relative_to(base))+':'+hashlib.sha256(p.read_bytes()).hexdigest())
 return hashlib.sha256('\n'.join(rows).encode()).hexdigest() if rows else ''
def _owned(base,slug,owner):
 if not owner:return False
 for d in (Path(base)/f'configs/{slug}',plant_artifact_dir(base,slug)):
  try:
   if (d/'.onboarding-owner').read_text()!=owner:return False
  except Exception:return False
 return True
def _claim(conn,vpn,now):
 token=secrets.token_urlsafe(24);rev=int(vpn['onboarding_revision'] or 0);conn.execute('begin immediate');cur=conn.execute("update vpns set reconcile_lock_token=?,reconcile_lock_until=? where id=? and active=0 and onboarding_revision=? and (reconcile_lock_until is null or reconcile_lock_until<? or reconcile_lock_token='')",(token,now+300,vpn['id'],rev,now));conn.commit()
 if cur.rowcount!=1:return None
 row=conn.execute('select * from vpns where id=? and reconcile_lock_token=?',(vpn['id'],token)).fetchone();return (dict(row),token,rev) if row else None
def _release(conn,vpn_id,token):conn.execute("update vpns set reconcile_lock_token='',reconcile_lock_until=null where id=? and reconcile_lock_token=?",(vpn_id,token));conn.commit()
def _store(conn,vpn,result,now,token,rev):return set_validation_state(conn,vpn['id'],result,now=now,expected_revision=rev,lock_token=token)
def _phase(conn,vpn_id,phase,token,rev,**values):
 sets=['generation_phase=?'];args=[phase]
 for k,v in values.items():sets.append(k+'=?');args.append(v)
 args += [vpn_id,rev,token];cur=conn.execute('update vpns set '+','.join(sets)+' where id=? and onboarding_revision=? and reconcile_lock_token=?',args);conn.commit()
 if cur.rowcount!=1:raise RuntimeError('La VPN cambió durante la reconciliación.')
def _container_info(runner,slug):return runner(['docker','inspect','--format','{{.Id}}|{{.RestartCount}}|{{index .Config.Labels "plantas.vpn.slug"}}|{{.Image}}|{{index .Config.Labels "plantas.vpn.owner"}}|{{index .Config.Labels "plantas.vpn.revision"}}|{{.State.Running}}','vpn-'+slug],timeout=10)
def _snapshot(runner,exclude):
 rc,out=runner(['docker','ps','-a','--format','{{.Names}}'],timeout=10)
 if rc!=0:return None
 snap={}
 for name in sorted(x.strip() for x in out.splitlines() if x.strip().startswith('vpn-') and x.strip()!='vpn-'+exclude):
  ir,iv=runner(['docker','inspect','--format','{{.Id}}|{{.RestartCount}}',name],timeout=10)
  if ir==0:snap[name]=iv.strip()
 return snap
def _expected(vpn):return runtime_image('ipsec',vpn.get('ipsec_engine') or 'libreswan') if vpn.get('vpn_type')=='ipsec' else runtime_image(vpn.get('vpn_type') or 'ssl')
def _certificate_codec(deps,seal):
 fn=deps.seal_certificate if seal else deps.unseal_certificate
 if fn:return fn
 import app as panel
 return panel.enc if seal else panel.dec
def _handle_ssl_certificate(conn,vpn,base,now,deps,token,rev,result):
 if vpn.get('vpn_type')!='ssl' or result.code not in {'container_not_running','daemon_not_running'}:return result,False
 rc,logs=deps.runner(['docker','logs','--tail','120','vpn-'+vpn['slug']],timeout=20)
 if rc!=0:return result,False
 digests=extract_certificate_digests(logs)
 if not digests:return result,False
 stored_enc=str(vpn.get('trusted_cert_enc') or '')
 if stored_enc:
  try:stored=str(_certificate_codec(deps,False)(stored_enc) or '').lower()
  except Exception:stored=''
  if not re.fullmatch(r'[a-f0-9]{64}',stored):return ValidationResult('blocked','certificate','certificate_state_invalid','La huella guardada no se puede validar.',False),False
  if any(x!=stored for x in digests):return ValidationResult('blocked','certificate','certificate_changed','El certificado del gateway cambió y requiere aceptación explícita.',False),False
  return result,False
 if len(digests)!=1:return ValidationResult('blocked','certificate','certificate_ambiguous','El gateway presentó información de certificado ambigua.',False),False
 if not int(vpn.get('accept_gateway_certificate') or 0):return ValidationResult('blocked','certificate','certificate_untrusted','El certificado presentado no fue autorizado durante el alta.',False),False
 digest=next(iter(digests))
 try:
  sealed=_certificate_codec(deps,True)(digest)
  if not isinstance(sealed,str) or not sealed:raise ValueError('seal failed')
  deps.cleanup(vpn,Path(base),deps.runner)
  cur=conn.execute("""update vpns set trusted_cert_enc=?,onboarding_state='draft',validation_stage='certificate',validation_code='pending',validation_detail='Certificado fijado; pendiente de regeneración controlada.',active=0,next_retry_at=?,retry_count=0,generation_phase='',generation_owner='',generated_manifest='',runtime_image_ref='',isolation_baseline_json='',publication_phase='',onboarding_revision=onboarding_revision+1 where id=? and onboarding_revision=? and reconcile_lock_token=?""",(sealed,now,vpn['id'],rev,token));conn.commit()
  if cur.rowcount!=1:raise RuntimeError('La VPN cambió durante la aceptación del certificado.')
 except RuntimeError:raise
 except Exception:return ValidationResult('blocked','certificate','certificate_acceptance_failed','No se pudo fijar el certificado de forma aislada.',False),False
 return None,True
def process_vpn(conn,vpn,base,now,deps,token,rev):
 vpn=dict(vpn);sl=vpn['slug'];cd=Path(base)/f'configs/{sl}';pd=plant_artifact_dir(base,sl);initial=vpn.get('onboarding_state') or 'draft';owner=str(vpn.get('generation_owner') or '')
 if initial!='draft' and vpn.get('generation_phase')=='generating':
  partials=[d for d in (cd,pd) if d.exists()]
  owned_partial=bool(owner) and all((d/'.onboarding-owner').is_file() and (d/'.onboarding-owner').read_text()==owner for d in partials)
  if not owned_partial:
   _store(conn,vpn,_blocked('artifact_ownership_failed','La generación interrumpida contiene artefactos sin ownership demostrable.'),now,token,rev);return
  for d in partials:shutil.rmtree(d)
  _phase(conn,vpn['id'],'',token,rev,generation_owner='',generated_manifest='',runtime_image_ref='');vpn.update(generation_phase='',generation_owner='',generated_manifest='',runtime_image_ref='');initial='draft';owner=''
 if initial=='deleting':
  try:
   deps.cleanup(vpn,Path(base),deps.runner)
   for sql,args in (("delete from permissions where equipment_id in (select id from equipment where plant=?)",(vpn['plant'],)),("delete from equipment_tags where equipment_id in (select id from equipment where plant=?)",(vpn['plant'],)),('delete from equipment where plant=?',(vpn['plant'],)),('delete from plant_permissions where plant=?',(vpn['plant'],))):
    try:conn.execute(sql,args)
    except sqlite3.OperationalError:pass
   cur=conn.execute("delete from vpns where id=? and onboarding_state='deleting' and reconcile_lock_token=? and onboarding_revision=?",(vpn['id'],token,rev));conn.commit()
   if cur.rowcount!=1:raise RuntimeError('La VPN cambió durante el cleanup.')
  except Exception:_store(conn,vpn,ValidationResult('blocked','cleanup','cleanup_failed','No se pudo completar la eliminación aislada; se conserva la evidencia.',False),now,token,rev)
  return
 if initial=='draft':
  ir,_=_container_info(deps.runner,sl)
  if ir==0:_store(conn,vpn,_blocked('container_collision','Ya existe un contenedor con este identificador VPN.'),now,token,rev);return
  if cd.exists() or pd.exists():
   if not _owned(base,sl,owner):_store(conn,vpn,_blocked('slug_files_collision','Existen artefactos no pertenecientes a este borrador.'),now,token,rev);return
  else:
   owner=secrets.token_urlsafe(24);_phase(conn,vpn['id'],'generating',token,rev,generation_owner=owner);vpn['generation_owner']=owner
   try:deps.generate(vpn,Path(base))
   except Exception:
    shutil.rmtree(cd,ignore_errors=True);shutil.rmtree(plant_artifact_dir(base,sl),ignore_errors=True);_store(conn,vpn,_blocked('generation_failed','No se pudo generar la configuración VPN.'),now,token,rev);return
  man=_manifest(base,sl)
  if not man:_store(conn,vpn,_blocked('generation_failed','Los artefactos generados están incompletos.'),now,token,rev);return
  _phase(conn,vpn['id'],'generated',token,rev,generated_manifest=man,runtime_image_ref=_expected(vpn));vpn['generated_manifest']=man
 else:
  if not _owned(base,sl,owner) or not vpn.get('generated_manifest') or _manifest(base,sl)!=vpn.get('generated_manifest'):_store(conn,vpn,_blocked('artifact_ownership_failed','Los artefactos no coinciden con el manifest del borrador.'),now,token,rev);return
 local=deps.static_validate(vpn,Path(base),deps.runner);_store(conn,vpn,local,now,token,rev)
 if local.code!='local_validated':return
 current_snapshot=_snapshot(deps.runner,sl)
 if current_snapshot is None:_store(conn,vpn,_isolation_blocked('isolation_snapshot_failed','No se pudo inventariar las VPN no relacionadas.'),now,token,rev);return
 baseline_raw=str(vpn.get('isolation_baseline_json') or '')
 if baseline_raw:
  try:baseline=json.loads(baseline_raw)
  except Exception:_store(conn,vpn,_isolation_blocked('isolation_baseline_invalid','El baseline de aislamiento no es válido.'),now,token,rev);return
  if current_snapshot!=baseline:_store(conn,vpn,_isolation_blocked('runtime_isolation_changed','Una VPN no relacionada difiere del baseline durable.'),now,token,rev);return
 else:
  baseline=current_snapshot;baseline_raw=json.dumps(baseline,sort_keys=True,separators=(',',':'));_phase(conn,vpn['id'],'validated',token,rev,isolation_baseline_json=baseline_raw);vpn['isolation_baseline_json']=baseline_raw
 _phase(conn,vpn['id'],'validated',token,rev);ir,info=_container_info(deps.runner,sl);need_start=ir!=0
 if ir==0:
  parts=info.strip().split('|');expected=_expected(vpn)
  if len(parts)>=7:
   if parts[2]!=sl or parts[3]!=expected or parts[4]!=owner or parts[5]!=str(rev):_store(conn,vpn,_blocked('runtime_ownership_failed','El contenedor no pertenece al owner/revisión/imagen del borrador.'),now,token,rev);return
   need_start=parts[6].lower()!='true'
  else:_store(conn,vpn,_blocked('runtime_ownership_failed','El runtime no expone labels de ownership completas.'),now,token,rev);return
 if need_start:
  before=baseline;_phase(conn,vpn['id'],'starting',token,rev);rc,_=deps.runner(start_spec(base,sl),timeout=90)
  if rc!=0:_store(conn,vpn,ValidationResult('offline','runtime','container_start_failed','No se pudo iniciar el contenedor aislado.',True),now,token,rev);return
  after=_snapshot(deps.runner,sl)
  if after is None or before!=after:_store(conn,vpn,_isolation_blocked('runtime_isolation_changed','Cambió una VPN no relacionada durante el arranque.'),now,token,rev);return
  _phase(conn,vpn['id'],'runtime_wait',token,rev)
 try:
  result=classify_evidence(vpn,deps.collect_runtime(vpn,deps.runner))
  final_snapshot=_snapshot(deps.runner,sl)
  if final_snapshot is None or final_snapshot!=baseline:result=_isolation_blocked('runtime_isolation_changed','Cambió una VPN no relacionada durante los gates.')
  result,certificate_handled=_handle_ssl_certificate(conn,vpn,base,now,deps,token,rev,result)
  if certificate_handled:return
  if result.state=='online' and int(vpn.get('auto_activate') if vpn.get('auto_activate') is not None else 1):
   if str(vpn.get('publication_phase') or '')=='published':result=ValidationResult('active','activation','active','Publicación durable ya completada; activación final recuperada.',False)
   else:
    _phase(conn,vpn['id'],str(vpn.get('generation_phase') or ''),token,rev,publication_phase='publishing');vpn['publication_phase']='publishing';result=deps.activate(conn,vpn,Path(base),deps.runner)
    if result.state=='active':_phase(conn,vpn['id'],str(vpn.get('generation_phase') or ''),token,rev,publication_phase='published');vpn['publication_phase']='published'
  _store(conn,vpn,result,now,token,rev)
 except Exception:_store(conn,vpn,ValidationResult('offline','runtime','runtime_probe_failed','No se pudo completar la comprobación del runtime VPN.',True),now,token,rev)
def _eligible(conn,now):return conn.execute('SELECT * FROM vpns WHERE active=0 AND (next_retry_at IS NULL OR next_retry_at<=?)',(now,)).fetchall()
def reconcile_once(conn,base,now=None,deps=None):
 now=int(time.time() if now is None else now);deps=deps or default_dependencies();ensure_onboarding_schema(conn);count=0;lock_dir=Path(os.environ.get('ONBOARDING_LOCK_DIR','/data/vpn-onboarding-locks'));lock_dir.mkdir(parents=True,exist_ok=True)
 for row in _eligible(conn,now):
  state=row['onboarding_state'] or 'draft';code=row['validation_code'] or ''
  if state=='draft' and code not in {'','pending'}:continue
  if state not in {'draft','validating','offline','control_plane_up','installed','deleting'}:continue
  fd=os.open(lock_dir/(row['slug']+'.lock'),os.O_CREAT|os.O_RDWR,0o600)
  try:
   try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   except BlockingIOError:continue
   claim=_claim(conn,row,now)
   if not claim:continue
   vpn,token,rev=claim
   try:
    try:process_vpn(conn,vpn,base,now,deps,token,rev);count+=1
    except RuntimeError:pass
   finally:_release(conn,vpn['id'],token)
  finally:os.close(fd)
 return count
def connect_db(path):
 conn=sqlite3.connect(path,timeout=10);conn.row_factory=sqlite3.Row;conn.execute('pragma busy_timeout=10000');conn.execute('pragma journal_mode=wal');return conn
def main():
 p=argparse.ArgumentParser();p.add_argument('--once',action='store_true');p.add_argument('--interval',type=int,default=30);args=p.parse_args();db=os.environ.get('PANEL_DB','/data/panel.db');base=Path(os.environ.get('PROJECT_DIR','/project'));cooldowns={};lock_dir=Path(os.environ.get('ONBOARDING_LOCK_DIR','/data/vpn-onboarding-locks'))
 while True:
  try:
   webfix_results=reconcile_webfix_namespaces(base,cooldowns=cooldowns,lock_dir=lock_dir)
   for slug,status in webfix_results.items():
    if status in {'repaired','compose_invalid','repair_failed','postcondition_failed','vpn_changed','discovery_failed','invalid_slug','invalid_ownership','inspection_failed','namespace_inspection_failed','cycle_failed'}:_webfix_log(slug,status)
  except Exception:_webfix_log('_system','cycle_failed')
  with connect_db(db) as conn:reconcile_once(conn,base)
  if args.once:return
  time.sleep(max(10,args.interval))
if __name__=='__main__':main()
