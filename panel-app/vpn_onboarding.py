from __future__ import annotations
import json,re,secrets,time
ONBOARDING_STATES={'draft','validating','waiting_gateway','waiting_target','blocked','active','offline','auth_failed','proposal_failed','control_plane_up','installed','online','verified_pending_activation','deleting'}
RETRYABLE_CODES={'peer_no_response','gateway_dns_failed','target_tcp_unreachable','container_missing','target_unreachable','ike_sa_missing','child_sa_missing','route_or_xfrm_missing','container_start_failed','runtime_probe_failed','tunnel_missing','route_missing','container_not_running','daemon_not_running','runtime_changed','vip_missing','runtime_isolation_changed'}
STAGE_TTL=900
TOKEN_RE=re.compile(r'^[A-Za-z0-9_-]{32,128}$')
STATE_COLUMNS={'onboarding_state':"TEXT DEFAULT 'active'",'validation_stage':"TEXT DEFAULT ''",'validation_code':"TEXT DEFAULT ''",'validation_detail':"TEXT DEFAULT ''",'validation_target_ip':"TEXT DEFAULT ''",'validation_target_port':'INTEGER','next_retry_at':'INTEGER','last_checked_at':'INTEGER','retry_count':'INTEGER DEFAULT 0','auto_activate':'INTEGER DEFAULT 1','accept_gateway_certificate':'INTEGER NOT NULL DEFAULT 0','profile_source':"TEXT DEFAULT ''",'phase1_proposals_json':"TEXT DEFAULT ''",'phase2_proposals_json':"TEXT DEFAULT ''",'remote_subnets_json':"TEXT DEFAULT ''",'dpd_retry_count':'INTEGER DEFAULT 3','dpd_retry_interval':'INTEGER DEFAULT 5','onboarding_revision':'INTEGER DEFAULT 0','reconcile_lock_token':"TEXT DEFAULT ''",'reconcile_lock_until':'INTEGER','generation_phase':"TEXT DEFAULT ''",'generation_owner':"TEXT DEFAULT ''",'generated_manifest':"TEXT DEFAULT ''",'runtime_image_ref':"TEXT DEFAULT ''",'isolation_baseline_json':"TEXT DEFAULT ''",'publication_phase':"TEXT DEFAULT ''",'web_onboarding_profile':"TEXT DEFAULT 'legacy'",'web_default_host':"TEXT DEFAULT ''"}
FORBIDDEN_KEYS={'password','password_enc','preshared_key','psk_enc','ciphertext','profile_enc','secret'}
def ensure_onboarding_schema(conn):
 conn.execute('pragma busy_timeout=5000')
 try:conn.execute('pragma journal_mode=WAL')
 except Exception:pass
 outer=conn.in_transaction
 try:
  conn.execute('savepoint onboarding_schema' if outer else 'begin immediate');cols={r[1] for r in conn.execute('pragma table_info(vpns)')}
  for name,kind in STATE_COLUMNS.items():
   if name not in cols:conn.execute(f'alter table vpns add column {name} {kind}')
  conn.execute("update vpns set onboarding_state='active' where onboarding_state is null or trim(onboarding_state)=''");conn.execute('create table if not exists forticlient_import_staging(token text primary key,owner text not null,profiles_enc text not null,created_ts integer not null)');conn.execute('create index if not exists ix_forticlient_stage_created on forticlient_import_staging(created_ts)')
  conn.execute('release onboarding_schema') if outer else conn.commit()
 except Exception:
  try:conn.execute('rollback to onboarding_schema');conn.execute('release onboarding_schema') if outer else None
  except Exception:
   if not outer:conn.rollback()
  raise
def _safe_profiles(profiles):
 if not isinstance(profiles,list) or not 1<=len(profiles)<=64:raise ValueError('Perfiles de importación no válidos.')
 def check(value):
  if isinstance(value,dict):
   for key,item in value.items():
    low=str(key).casefold()
    if low in FORBIDDEN_KEYS or low.endswith('_enc'):raise ValueError('El staging no admite secretos.')
    check(item)
  elif isinstance(value,list):
   if len(value)>128:raise ValueError('El perfil normalizado supera los límites.')
   for item in value:check(item)
  elif isinstance(value,str):
   if len(value)>4096 or value.lstrip().lower().startswith('encx '):raise ValueError('El staging no admite material cifrado de origen.')
  elif value is not None and not isinstance(value,(bool,int,float)):raise ValueError('Tipo normalizado no válido.')
 check(profiles);return profiles
def stage_profiles(conn,owner,profiles,encrypt,now=None):
 owner=str(owner or '')
 if not owner:raise ValueError('Propietario de staging obligatorio.')
 payload=json.dumps(_safe_profiles(profiles),ensure_ascii=False,separators=(',',':'),sort_keys=True);sealed=encrypt(payload)
 if not isinstance(sealed,str) or not sealed:raise ValueError('No se pudo cifrar el staging.')
 now=int(time.time() if now is None else now);token=secrets.token_urlsafe(32);conn.execute('delete from forticlient_import_staging where created_ts<?',(now-STAGE_TTL,));conn.execute('insert into forticlient_import_staging(token,owner,profiles_enc,created_ts) values(?,?,?,?)',(token,owner,sealed,now));conn.commit();return token
def load_stage(conn,owner,token,decrypt,now=None):
 if not TOKEN_RE.fullmatch(str(token or '')):return None
 now=int(time.time() if now is None else now);row=conn.execute('select profiles_enc from forticlient_import_staging where token=? and owner=? and created_ts>=?',(token,str(owner or ''),now-STAGE_TTL)).fetchone()
 if not row:return None
 try:return _safe_profiles(json.loads(decrypt(row[0])))
 except Exception:return None
def consume_stage(conn,owner,token,commit=True):
 if not TOKEN_RE.fullmatch(str(token or '')):return False
 cur=conn.execute('delete from forticlient_import_staging where token=? and owner=?',(token,str(owner or '')))
 if commit:conn.commit()
 return cur.rowcount==1
def retry_delay(code,retry_count):
 retry_count=max(0,int(retry_count or 0));target={'target_tcp_unreachable','target_unreachable','route_missing'};control={'peer_no_response','gateway_dns_failed','container_missing','ike_sa_missing','child_sa_missing','route_or_xfrm_missing','container_start_failed','runtime_probe_failed','tunnel_missing','container_not_running','daemon_not_running','runtime_changed','vip_missing','runtime_isolation_changed'};schedule=(60,300,900) if code in target else ((60,300,900,1800) if code in control else ())
 return schedule[min(retry_count,len(schedule)-1)] if schedule else None

def set_validation_state(conn,vpn_id,result,now=None,expected_revision=None,lock_token=None):
 getter=result.get if hasattr(result,'get') else lambda key,default=None:getattr(result,key,default)
 state=str(getter('state',''));stage=str(getter('stage',''));code=str(getter('code',''));message=str(getter('public_message',''))
 if state not in ONBOARDING_STATES:raise ValueError('Estado de onboarding no válido.')
 if not re.fullmatch(r'[a-z0-9_]{1,64}',code) or not re.fullmatch(r'[a-z0-9_]{1,64}',stage):raise ValueError('Código de validación no válido.')
 if len(message)>500 or re.search(r'(?i)(?:password|psk|secret|xauth)\s*[=:]|EncX\s',message):raise ValueError('El diagnóstico contiene material no permitido.')
 row=conn.execute('select retry_count,auto_activate from vpns where id=?',(vpn_id,)).fetchone()
 if not row:raise ValueError('VPN no encontrada.')
 previous=int(row[0] or 0);auto_activate=int(row[1] if row[1] is not None else 1)
 if state=='online' and not auto_activate:
  state='verified_pending_activation';stage='activation';code='verified_pending_activation';message='VPN verificada; pendiente de activación administrativa.'
 is_active=state in {'active','online'};retry=bool(getter('retryable',getter('retry',False))) and code in RETRYABLE_CODES and not is_active;delay=retry_delay(code,previous) if retry else None;stamp=int(time.time() if now is None else now);next_retry=stamp+delay if delay is not None else None;count=previous+1 if retry else (0 if is_active else previous);active=1 if is_active else 0
 sql='update vpns set onboarding_state=?,validation_stage=?,validation_code=?,validation_detail=?,last_checked_at=?,next_retry_at=?,retry_count=?,active=? where id=?';params=[state,stage,code,message,stamp,next_retry,count,active,vpn_id]
 if expected_revision is not None:sql+=' and onboarding_revision=?';params.append(int(expected_revision))
 if lock_token is not None:sql+=' and reconcile_lock_token=?';params.append(str(lock_token))
 cur=conn.execute(sql,params);conn.commit()
 if cur.rowcount!=1:raise RuntimeError('La VPN cambió durante la reconciliación.')
 return True
