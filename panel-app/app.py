import threading
import fcntl,functools

import os, sqlite3, secrets, functools, subprocess, re, time, html, shutil, csv, io, ipaddress, unicodedata, json, hmac, stat
from urllib.parse import quote
from datetime import datetime
from flask import Flask,g,request,redirect,session,flash,abort,get_flashed_messages,Response,has_request_context,jsonify
from werkzeug.security import generate_password_hash,check_password_hash
from cryptography.fernet import Fernet
from vpn_onboarding import ensure_onboarding_schema,stage_profiles,load_stage,consume_stage
from vpn_endpoint_health import apply_probe_result, ensure_endpoint_health_schema, health_for_vpns, history_intervals, public_alert_eligible, configure_sqlite_connection, StaleRevisionError, StaleCycleError, target_revision, validate_result
from forticlient_import import parse_forticlient_backup,FortiClientProfileError,MAX_FORTICLIENT_BYTES
from vpn_runtime import runtime_image,proposal_rows,expand_ike_proposals,remote_subnets
DATA_DIR=os.environ.get('PANEL_DATA_DIR','/data'); os.makedirs(DATA_DIR,exist_ok=True)
DB=os.environ.get('PANEL_DB',os.path.join(DATA_DIR,'panel.db')); BASE=os.environ.get('PROJECT_DIR','/opt/bastion-vpn')
PUBLIC_ORIGIN=os.environ.get('BASTION_PUBLIC_ORIGIN','http://127.0.0.1').rstrip('/')
DEFAULT_VALIDATION_DENY_CIDRS=('127.0.0.0/8','169.254.0.0/16','100.64.0.0/10')
def validation_deny_networks():
    raw=os.environ.get('VALIDATION_DENY_CIDRS',' '.join(DEFAULT_VALIDATION_DENY_CIDRS))
    return [ipaddress.ip_network(value) for value in raw.replace(',',' ').split() if value]

def k(path,gen):
    if os.path.exists(path):
        with open(path,'rb') as fh: return fh.read().strip()
    v=gen()
    with open(path,'wb') as fh: fh.write(v)
    os.chmod(path,0o600); return v
app=Flask(__name__); app.secret_key=k(os.path.join(DATA_DIR,'secret.key'),lambda:secrets.token_hex(32).encode()).decode(); F=Fernet(k(os.path.join(DATA_DIR,'fernet.key'),Fernet.generate_key))
EQUIPMENT_TAG_CATALOG=('Scada','Trackers','Inversores','CCTV','SET')
EQUIPMENT_TAG_SLUGS={'Scada':'scada','Trackers':'trackers','Inversores':'inversores','CCTV':'cctv','SET':'set'}

VPN_TYPES={'ssl','ipsec','pptp','openvpn'}
OPENVPN_MAX_BYTES=1024*1024
app.config['MAX_CONTENT_LENGTH']=OPENVPN_MAX_BYTES+65536
OPENVPN_ALLOWED={'client','dev','proto','remote','nobind','persist-key','persist-tun','resolv-retry','cipher','data-ciphers','auth','remote-cert-tls','verify-x509-name','auth-user-pass','route','redirect-gateway','verb'}
OPENVPN_INLINE={'ca','cert','key','tls-auth','tls-crypt'}
OPENVPN_FORBIDDEN={'up','down','route-up','route-pre-down','client-connect','learn-address','plugin','script-security','management','setenv','tls-verify','ca','cert','key','tls-auth','tls-crypt'}

def ensure_openvpn_import_staging(conn):
    conn.execute('CREATE TABLE IF NOT EXISTS openvpn_import_staging(token TEXT PRIMARY KEY, username TEXT NOT NULL, plant TEXT NOT NULL, slug TEXT NOT NULL, host TEXT NOT NULL, port TEXT NOT NULL, requires_auth INTEGER NOT NULL, requires_key_pass INTEGER NOT NULL, routes TEXT NOT NULL, profile_enc TEXT NOT NULL, created_ts INTEGER NOT NULL)')

def stage_openvpn_import(conn, username, form, parsed, profile_bytes):
    profile=bytes(profile_bytes).decode('utf-8-sig')
    if parsed.get('profile')!=profile: raise ValueError('El perfil OpenVPN no coincide con el análisis validado.')
    plant=(form.get('plant') or '').strip(); sl=slug((form.get('slug') or plant).strip())
    if not username or not plant or not sl: raise ValueError('Importación OpenVPN incompleta.')
    token=secrets.token_urlsafe(32)
    conn.execute('DELETE FROM openvpn_import_staging WHERE created_ts<?',(int(time.time())-900,))
    conn.execute('INSERT INTO openvpn_import_staging(token,username,plant,slug,host,port,requires_auth,requires_key_pass,routes,profile_enc,created_ts) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(token,username,plant,sl,parsed['host'],parsed['port'],int(bool(parsed['requires_auth'])),int(bool(parsed['requires_key_pass'])),','.join(parsed['routes']),enc(profile),int(time.time())))
    conn.commit(); return token

def load_openvpn_import(conn, username, token):
    if not re.fullmatch(r'[A-Za-z0-9_-]{32,128}',str(token or '')): return None
    row=conn.execute('SELECT * FROM openvpn_import_staging WHERE token=? AND username=? AND created_ts>=?',(token,username,int(time.time())-900)).fetchone()
    if not row:return None
    profile=dec(row['profile_enc'])
    if not profile:return None
    return {'plant':row['plant'],'slug':row['slug'],'host':row['host'],'port':row['port'],'requires_auth':bool(row['requires_auth']),'requires_key_pass':bool(row['requires_key_pass']),'routes':(row['routes'].split(',') if row['routes'] else []),'profile':profile}
def consume_openvpn_import(conn, username, token, commit=True):
    if not re.fullmatch(r'[A-Za-z0-9_-]{32,128}',str(token or '')):return False
    cur=conn.execute('DELETE FROM openvpn_import_staging WHERE token=? AND username=?',(token,username))
    if commit:conn.commit()
    return cur.rowcount==1

def migrate_vpn_access_columns(conn):
    columns={row[1] for row in conn.execute('PRAGMA table_info(vpns)')}
    additions={
        'openvpn_profile_enc':"TEXT DEFAULT ''", 'openvpn_key_pass_enc':"TEXT DEFAULT ''",
        'openvpn_requires_auth':'INTEGER DEFAULT 0', 'openvpn_requires_key_pass':'INTEGER DEFAULT 0',
        'openvpn_routes':"TEXT DEFAULT ''",
    }
    for name,typ in additions.items():
        if name not in columns:
            conn.execute(f'ALTER TABLE vpns ADD COLUMN {name} {typ}')
            columns.add(name)

def parse_openvpn_profile(raw):
    if not isinstance(raw,(bytes,bytearray)) or not raw or len(raw)>OPENVPN_MAX_BYTES:
        raise ValueError('El perfil OpenVPN está vacío o supera el límite permitido.')
    if b'\0' in raw: raise ValueError('El perfil OpenVPN contiene NUL.')
    try: text=bytes(raw).decode('utf-8-sig')
    except UnicodeDecodeError as exc: raise ValueError('El perfil OpenVPN debe estar codificado en UTF-8.') from exc
    remote=None; proto='udp'; routes=[]; requires_auth=False; key_lines=[]; active_inline=None; saw_client=False; saw_dev=False
    for raw_line in text.splitlines():
        line=raw_line.strip()
        if not line or line.startswith(('#',';')): continue
        tag=re.fullmatch(r'<(/?)([A-Za-z0-9-]+)>',line)
        if tag:
            closing,name=tag.groups();name=name.lower()
            if name not in OPENVPN_INLINE: raise ValueError('Bloque OpenVPN no permitido.')
            if closing:
                if active_inline!=name: raise ValueError('Bloques OpenVPN mal balanceados.')
                active_inline=None
            else:
                if active_inline: raise ValueError('Bloques OpenVPN anidados no permitidos.')
                active_inline=name
            continue
        if active_inline:
            if active_inline=='key': key_lines.append(raw_line)
            continue
        parts=line.split(); directive=parts[0].lower(); args=parts[1:]
        if directive in OPENVPN_FORBIDDEN or directive not in OPENVPN_ALLOWED:
            raise ValueError('Directiva OpenVPN no permitida: '+directive+'.')
        if directive=='client':
            if args: raise ValueError('Directiva client no admite argumentos.')
            saw_client=True
        elif directive=='dev':
            if len(args)!=1 or not re.fullmatch(r'tun[0-9]*',args[0]): raise ValueError('Solo se permiten interfaces tun OpenVPN.')
            saw_dev=True
        elif directive=='proto':
            if len(args)!=1 or args[0].lower() not in {'udp','udp4','udp6','tcp','tcp4','tcp6','tcp-client','tcp4-client','tcp6-client'}: raise ValueError('Protocolo OpenVPN no permitido.')
            proto=args[0].lower()
        elif directive=='remote':
            if remote is not None or len(args) not in {1,2,3}: raise ValueError('El perfil debe contener un único remote válido.')
            host=args[0]
            if not re.fullmatch(r'[A-Za-z0-9.-]+',host): raise ValueError('Gateway OpenVPN no válido.')
            port=args[1] if len(args)>=2 else '1194'
            if not port.isdigit() or not 1<=int(port)<=65535: raise ValueError('Puerto OpenVPN fuera de rango.')
            remote=(host,port)
        elif directive=='auth-user-pass':
            if args: raise ValueError('auth-user-pass no puede referenciar un archivo externo.')
            requires_auth=True
        elif directive=='route':
            if len(args)!=2: raise ValueError('Cada route debe incluir red y máscara.')
            try: route=str(ipaddress.ip_network((args[0],args[1]),strict=False))
            except ValueError as exc: raise ValueError('Ruta OpenVPN no válida.') from exc
            if route not in routes: routes.append(route)
        elif directive=='redirect-gateway' and any(arg not in {'def1','bypass-dhcp','bypass-dns','local','autolocal','block-local'} for arg in args):
            raise ValueError('Argumento redirect-gateway no permitido.')
        elif directive in {'nobind','persist-key','persist-tun'} and args:
            raise ValueError('Directiva OpenVPN sin argumentos inválida.')
    if active_inline: raise ValueError('Bloque OpenVPN sin cierre.')
    if not (saw_client and saw_dev and remote): raise ValueError('El perfil debe incluir client, dev tun y remote.')
    encrypted=any('BEGIN ENCRYPTED PRIVATE KEY' in line or 'Proc-Type: 4,ENCRYPTED' in line for line in key_lines)
    return {'host':remote[0],'port':remote[1],'proto':proto,'routes':routes,'requires_auth':requires_auth,'requires_key_pass':encrypted,'profile':text}
def enc(x): return F.encrypt((x or '').encode()).decode()
def dec(x):
    try: return F.decrypt((x or '').encode()).decode() if x else ''
    except Exception: return ''
def _connect_db():
    conn=configure_sqlite_connection(sqlite3.connect(DB, timeout=5.0))
    conn.row_factory=sqlite3.Row
    return conn
def db():
    if 'db' not in g: g.db=_connect_db()
    return g.db
_vpn_lock_local=threading.local()
class vpn_slug_lock:
 def __init__(self,slug,blocking=True):self.slug=slug;self.blocking=blocking;self.fd=None;self.reentrant=False
 def __enter__(self):
  held=getattr(_vpn_lock_local,'held',set())
  if self.slug in held:self.reentrant=True;return self
  lock_dir=os.environ.get('ONBOARDING_LOCK_DIR','/data/vpn-onboarding-locks');os.makedirs(lock_dir,mode=0o700,exist_ok=True);self.fd=os.open(os.path.join(lock_dir,self.slug+'.lock'),os.O_CREAT|os.O_RDWR,0o600)
  try:fcntl.flock(self.fd,fcntl.LOCK_EX if self.blocking else fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:os.close(self.fd);self.fd=None;raise
  _vpn_lock_local.held=held|{self.slug};return self
 def __exit__(self,*exc):
  if not self.reentrant:
   held=getattr(_vpn_lock_local,'held',set());_vpn_lock_local.held=held-{self.slug};fcntl.flock(self.fd,fcntl.LOCK_UN);os.close(self.fd)
def vpn_mutation_lock(fn):
 @functools.wraps(fn)
 def wrapped(i,*args,**kwargs):
  row=db().execute('select slug from vpns where id=?',(i,)).fetchone()
  if not row:return fn(i,*args,**kwargs)
  with vpn_slug_lock(row['slug']):return fn(i,*args,**kwargs)
 return wrapped
def _inspect_exact(name,fmt):
 try:
  p=subprocess.run(['docker','inspect','--format',fmt,name],text=True,capture_output=True,timeout=15);return p.returncode,p.stdout.strip()
 except (FileNotFoundError,subprocess.TimeoutExpired):return 127,''
def _remove_exact(name,expected_service=None,expected_slug=None,expected_image=None):
 rc,out=_inspect_exact(name,'{{index .Config.Labels "com.docker.compose.service"}}|{{index .Config.Labels "plantas.vpn.slug"}}|{{index .Config.Labels "plantas.vpn.onboarding"}}|{{.Image}}')
 if rc!=0:return
 service,slug,onboarding,image=(out.split('|')+['','','',''])[:4]
 if expected_service and service!=expected_service:raise RuntimeError('Ownership de servicio no válido.')
 if expected_slug and (slug!=expected_slug or onboarding!='true'):raise RuntimeError('Ownership VPN no válido.')
 if expected_image and image!=expected_image:raise RuntimeError('Imagen de runtime distinta del manifest.')
 p=subprocess.run(['docker','rm','-f',name],text=True,capture_output=True,timeout=45)
 if p.returncode!=0:raise RuntimeError('No se pudo eliminar el contenedor exacto.')
def _owned_dirs(v):
 sl=v['slug'];owner=str(v['generation_owner'] or '') if 'generation_owner' in v.keys() else ''
 for d in (os.path.join(BASE,'configs',sl),os.path.join(BASE,'sites',sl)):
  if os.path.exists(d):
   marker=os.path.join(d,'.onboarding-owner')
   if not owner or not os.path.isfile(marker) or open(marker,encoding='utf-8').read()!=owner:raise RuntimeError('Artefactos ajenos al borrador.')
def prepare_draft_edit(i):
 v=db().execute('select * from vpns where id=?',(i,)).fetchone()
 if not v or int(v['active'] or 0):return
 _owned_dirs(v);_remove_exact('vpn-'+v['slug'],expected_slug=v['slug'],expected_image=(v['runtime_image_ref'] or None) if 'runtime_image_ref' in v.keys() else None)
 for d in (os.path.join(BASE,'configs',v['slug']),os.path.join(BASE,'sites',v['slug'])):
  if os.path.exists(d):shutil.rmtree(d)
 db().execute("update vpns set generation_phase='',generation_owner='',generated_manifest='',runtime_image_ref='' where id=?",(i,));db().commit()

@app.teardown_appcontext
def close(e):
    if 'db' in g: g.db.close()
def normalize_plant_name(value): return unicodedata.normalize('NFC',' '.join(str(value or '').split()))
def plant_key(value): return normalize_plant_name(value).casefold()
def normalize_plant_data(conn):
    canonical={}
    for table in ('vpns','equipment'):
        for _,plant in conn.execute(f'SELECT id,plant FROM {table} WHERE plant IS NOT NULL ORDER BY id'):
            key=plant_key(plant)
            if key and key not in canonical: canonical[key]=normalize_plant_name(plant)
    for table in ('vpns','equipment'):
        for row_id,plant in conn.execute(f'SELECT id,plant FROM {table} WHERE plant IS NOT NULL').fetchall():
            target=canonical.get(plant_key(plant),normalize_plant_name(plant))
            if plant!=target: conn.execute(f'UPDATE {table} SET plant=? WHERE id=?',(target,row_id))
    for user_id,plant in conn.execute('SELECT user_id,plant FROM plant_permissions').fetchall():
        target=canonical.get(plant_key(plant),normalize_plant_name(plant))
        if plant!=target:
            conn.execute('INSERT OR IGNORE INTO plant_permissions(user_id,plant) VALUES(?,?)',(user_id,target));conn.execute('DELETE FROM plant_permissions WHERE user_id=? AND plant=?',(user_id,plant))
    for token,plant in conn.execute('SELECT token,plant FROM equipment_import_batches').fetchall():
        target=canonical.get(plant_key(plant),normalize_plant_name(plant))
        if plant!=target: conn.execute('UPDATE equipment_import_batches SET plant=? WHERE token=?',(target,token))
def validate_config_secret(value,label='secreto'):
    value=str(value or '')
    if any(ord(ch)<32 or ord(ch)==127 for ch in value): raise ValueError(label+' contiene caracteres de control no permitidos.')
    return value
def strongswan_quote(value,label='secreto'):
    value=validate_config_secret(value,label)
    return '"'+value.replace('\\','\\\\').replace('\"','\\\"')+'"'
def write_private_text(path,text):
    directory=os.path.dirname(path);os.makedirs(directory,mode=0o700,exist_ok=True);tmp=os.path.join(directory,'.tmp-'+secrets.token_urlsafe(18));fd=None
    try:
        fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as fh:fd=None;fh.write(text);fh.flush();os.fsync(fh.fileno())
        os.replace(tmp,path);os.chmod(path,0o600);dfd=os.open(directory,os.O_RDONLY)
        try:os.fsync(dfd)
        finally:os.close(dfd)
    except Exception:
        if fd is not None:os.close(fd)
        try:os.unlink(tmp)
        except FileNotFoundError:pass
        raise
def _stage_text(path,content,mode):
    directory=os.path.dirname(path) or '.'; temp=os.path.join(directory,'.'+os.path.basename(path)+'.tmp-'+str(os.getpid())+'-'+secrets.token_hex(4)); fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'w',encoding='utf-8') as fh: fd=None; fh.write(content); fh.flush(); os.fsync(fh.fileno())
        return temp
    except Exception:
        if fd is not None: os.close(fd)
        try: os.unlink(temp)
        except FileNotFoundError: pass
        raise
def _backup_for_replace(path):
    if not os.path.exists(path): return None
    backup=os.path.join(os.path.dirname(path) or '.','.'+os.path.basename(path)+'.bak-'+secrets.token_hex(4))
    try: os.link(path,backup)
    except OSError: shutil.copy2(path,backup)
    return backup
def write_ipsec_pair(conf_path,conf,secret_path,secret):
    conf_tmp=secret_tmp=conf_backup=secret_backup=None; replaced=set()
    try:
        conf_tmp=_stage_text(conf_path,conf,0o644); secret_tmp=_stage_text(secret_path,secret,0o600)
        conf_backup=_backup_for_replace(conf_path); secret_backup=_backup_for_replace(secret_path)
        os.replace(conf_tmp,conf_path); conf_tmp=None; replaced.add(conf_path)
        os.replace(secret_tmp,secret_path); secret_tmp=None; replaced.add(secret_path)
        directory=os.path.dirname(conf_path) or '.'
        try:
            dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            try: os.fsync(dfd)
            finally: os.close(dfd)
        except (AttributeError,OSError): pass
    except Exception:
        for path,backup in ((secret_path,secret_backup),(conf_path,conf_backup)):
            try:
                if backup and os.path.exists(backup): os.replace(backup,path)
                elif path in replaced: os.unlink(path)
            except FileNotFoundError: pass
        raise
    finally:
        for path in (conf_tmp,secret_tmp,conf_backup,secret_backup):
            if path:
                try: os.unlink(path)
                except FileNotFoundError: pass

def require_mapped(mapping,value,label):
    key=str(value or '').lower()
    if key not in mapping: raise ValueError(label+' no válido.')
    return mapping[key]
def ensure_bootstrap_admin(conn,now):
    if conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]: return
    password=os.environ.get('PANEL_BOOTSTRAP_ADMIN_PASSWORD','')
    if len(password)<16 or any(ord(ch)<32 or ord(ch)==127 for ch in password):
        raise RuntimeError('PANEL_BOOTSTRAP_ADMIN_PASSWORD es obligatorio y debe tener al menos 16 caracteres para una base nueva.')
    conn.execute('INSERT INTO users(id,username,password_hash,role,active,created_at) VALUES(1,?,?,?,?,?)',('admin',generate_password_hash(password),'admin',1,now))

def ensure_monitor_lease_schema(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS vpn_endpoint_monitor_leases(
        vpn_id INTEGER PRIMARY KEY,
        target_generation INTEGER NOT NULL,
        cycle_id INTEGER NOT NULL,
        lease_id TEXT NOT NULL,
        issued_at INTEGER NOT NULL
    )""")

def init():
    c=_connect_db(); now=datetime.now().isoformat(timespec='seconds')
    for q in [
    'CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, role TEXT, active INTEGER, created_at TEXT)',
    'CREATE TABLE IF NOT EXISTS equipment(id INTEGER PRIMARY KEY, plant TEXT, name TEXT, kind TEXT, real_ip TEXT, real_port TEXT, path TEXT, public_url TEXT, description TEXT, active INTEGER, created_at TEXT, vpn_id INTEGER)',
    'CREATE TABLE IF NOT EXISTS tags(id INTEGER PRIMARY KEY, name TEXT UNIQUE, sort_order INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS equipment_tags(equipment_id INTEGER, tag_id INTEGER, PRIMARY KEY(equipment_id,tag_id))',
    'CREATE TABLE IF NOT EXISTS permissions(user_id INTEGER, equipment_id INTEGER, PRIMARY KEY(user_id,equipment_id))',
    'CREATE TABLE IF NOT EXISTS plant_permissions(user_id INTEGER, plant TEXT, PRIMARY KEY(user_id,plant))',
    'CREATE TABLE IF NOT EXISTS equipment_import_batches(token TEXT PRIMARY KEY, user_id INTEGER, plant TEXT, csv_enc TEXT, created_ts INTEGER)',
    'CREATE TABLE IF NOT EXISTS vpns(id INTEGER PRIMARY KEY, plant TEXT, slug TEXT UNIQUE, host TEXT, port TEXT, username TEXT, password_enc TEXT, trusted_cert_enc TEXT, active INTEGER, created_at TEXT)']:
        c.execute(q)
    for sort_order,name in enumerate(EQUIPMENT_TAG_CATALOG):
        c.execute('INSERT OR IGNORE INTO tags(name,sort_order) VALUES(?,?)',(name,sort_order))
        c.execute('UPDATE tags SET sort_order=? WHERE name=?',(sort_order,name))
    cols=[r[1] for r in c.execute('PRAGMA table_info(equipment)').fetchall()]
    if 'vpn_id' not in cols: c.execute('ALTER TABLE equipment ADD COLUMN vpn_id INTEGER')
    for name,typ in {'proxy_port':'INTEGER','rdp_username_enc':'TEXT','rdp_password_enc':'TEXT','rdp_domain_enc':'TEXT','rdp_remote_app':'TEXT','vnc_password_enc':'TEXT','vnc_read_only':'INTEGER DEFAULT 0','web_mode':"TEXT DEFAULT 'auto'",'web_effective_mode':"TEXT DEFAULT 'direct'",'web_diagnostic':"TEXT DEFAULT ''",'web_proxy_port':'INTEGER'}.items():
        if name not in cols: c.execute(f'ALTER TABLE equipment ADD COLUMN {name} {typ}')
    vcols=[r[1] for r in c.execute('PRAGMA table_info(vpns)').fetchall()]
    extra_cols={
        'vpn_type':"TEXT DEFAULT 'ssl'", 'ipsec_engine':"TEXT DEFAULT 'libreswan'", 'psk_enc':'TEXT', 'ike_version':"TEXT DEFAULT 'ikev1'",
        'aggressive':'INTEGER DEFAULT 0', 'phase1_enc':"TEXT DEFAULT 'aes256'", 'phase1_auth':"TEXT DEFAULT 'sha512'",
        'dh_group':"TEXT DEFAULT '14'", 'phase1_enc2':"TEXT DEFAULT ''", 'phase1_auth2':"TEXT DEFAULT ''", 'dh_groups':"TEXT DEFAULT ''",
        'phase1_lifetime':"TEXT DEFAULT '86400'", 'dpd':'INTEGER DEFAULT 1', 'nat_traversal':'INTEGER DEFAULT 1',
        'phase2_enc':"TEXT DEFAULT 'aes256'", 'phase2_auth':"TEXT DEFAULT 'sha512'", 'phase2_enc2':"TEXT DEFAULT ''", 'phase2_auth2':"TEXT DEFAULT ''",
        'phase2_lifetime':"TEXT DEFAULT '43200'", 'pfs':'INTEGER DEFAULT 1', 'pfs_group':"TEXT DEFAULT ''", 'local_id':'TEXT', 'remote_id':'TEXT', 'modecfg':"TEXT DEFAULT 'pull'", 'auth_mode':"TEXT DEFAULT ''", 'remote_subnet':"TEXT DEFAULT '0.0.0.0/0'"
    }
    for name,typ in extra_cols.items():
        if name not in vcols:
            try: c.execute(f'ALTER TABLE vpns ADD COLUMN {name} {typ}')
            except sqlite3.OperationalError as e:
                if 'duplicate column name' not in str(e): raise
    migrate_vpn_access_columns(c)
    ensure_openvpn_import_staging(c)
    ensure_onboarding_schema(c)
    ensure_endpoint_health_schema(c)
    ensure_monitor_lease_schema(c)
    c.execute("UPDATE vpns SET ipsec_engine='libreswan' WHERE ipsec_engine IS NULL OR trim(ipsec_engine)=''")
    c.execute("UPDATE vpns SET ipsec_engine='strongswan' WHERE ike_version='ikev2'")
    c.execute("UPDATE vpns SET dh_groups=dh_group WHERE dh_groups IS NULL OR trim(dh_groups)=''")
    c.execute("UPDATE vpns SET pfs_group=dh_group WHERE pfs=1 AND (pfs_group IS NULL OR trim(pfs_group)='')")
    normalize_plant_data(c)
    try: c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_vpns_plant_normalized ON vpns(lower(trim(plant))) WHERE trim(plant)<>''")
    except sqlite3.IntegrityError: pass
    ensure_bootstrap_admin(c,now)
    c.commit(); c.close()
init()
def normalize_equipment_tags(values):
    if isinstance(values,str): values=re.split(r'[|,]',values)
    values=list(values or [])
    catalog={name.casefold():name for name in EQUIPMENT_TAG_CATALOG};selected=set()
    for raw in values:
        value=str(raw or '').strip()
        if not value: continue
        canonical=catalog.get(value.casefold())
        if not canonical: raise ValueError('Tag no válido: '+value+'. Use: '+', '.join(EQUIPMENT_TAG_CATALOG))
        selected.add(canonical)
    return [name for name in EQUIPMENT_TAG_CATALOG if name in selected]
def set_equipment_tags(conn,equipment_id,names):
    names=normalize_equipment_tags(names)
    conn.execute('DELETE FROM equipment_tags WHERE equipment_id=?',(equipment_id,))
    for name in names:
        conn.execute('INSERT INTO equipment_tags(equipment_id,tag_id) SELECT ?,id FROM tags WHERE name=?',(equipment_id,name))
def equipment_tag_names(conn,equipment_id):
    return [row['name'] for row in conn.execute('SELECT t.name FROM equipment_tags et JOIN tags t ON t.id=et.tag_id WHERE et.equipment_id=? ORDER BY t.sort_order,t.id',(equipment_id,))]
def equipment_tag_slug(name): return EQUIPMENT_TAG_SLUGS.get(name,'')
def equipment_tag_badges(names):
    return ''.join(f"<span class='badge tag-badge tag-{equipment_tag_slug(name)}'>{html.escape(name)}</span>" for name in names) or "<span class='muted'>—</span>"
def equipment_tag_filter_controls():
    options=''.join(f"<label class='tag-filter-option tag-{equipment_tag_slug(name)}'><input type='checkbox' data-filter-tag='{html.escape(name,quote=True)}' onchange='filterEquipmentTags(this)'><span>{html.escape(name)}</span></label>" for name in EQUIPMENT_TAG_CATALOG)
    return "<section class='tag-filter' data-tag-filter data-table-id='equipment-table'><div class='tag-filter-head'><strong>Filtrar por tags</strong><span class='muted' data-filter-count>Todos los equipos</span></div><div class='tag-filter-options'>"+options+"<button class='btn tag-filter-clear' type='button' data-filter-clear onclick='clearEquipmentTagFilters(this)' disabled>Limpiar</button></div></section>"
def me():
    return db().execute('SELECT * FROM users WHERE id=? AND active=1',(session.get('uid'),)).fetchone() if session.get('uid') else None
def need(f):
    @functools.wraps(f)
    def w(*a,**kw): return f(*a,**kw) if me() else redirect('/login')
    return w
def admin(f):
    @functools.wraps(f)
    def w(*a,**kw):
        u=me()
        if not u: return redirect('/login')
        if u['role']!='admin': abort(403)
        return f(*a,**kw)
    return w

ENDPOINT_PUBLIC_ALERTS_ENV='VPN_ENDPOINT_PUBLIC_ALERTS_ENABLED'
ENDPOINT_MONITOR_COLLECTION_ENV='VPN_ENDPOINT_MONITOR_COLLECTION_ENABLED'
ENDPOINT_ADMIN_DIAGNOSTICS_ENV='VPN_ENDPOINT_ADMIN_DIAGNOSTICS_ENABLED'
def _feature_enabled(name):
    return os.environ.get(name,'false').strip().lower() in {'1','true','yes','on'}
def endpoint_public_alerts_enabled():
    return _feature_enabled(ENDPOINT_PUBLIC_ALERTS_ENV)
def endpoint_monitor_collection_enabled():
    return _feature_enabled(ENDPOINT_MONITOR_COLLECTION_ENV)
def endpoint_admin_diagnostics_enabled():
    return _feature_enabled(ENDPOINT_ADMIN_DIAGNOSTICS_ENV)

ENDPOINT_STATE_LABELS={'accessible':'Accesible','unreachable':'No accesible'}
ENDPOINT_CODE_LABELS={'not_checked':'Sin datos','icmp_reply':'ICMP: OK','icmp_timeout':'ICMP: Fallo','icmp_unreachable':'ICMP: Fallo','icmp_probe_error':'ICMP: Error de sonda','tcp_accept':'TCP: OK','tcp_unreachable':'TCP: Fallo','ike_response':'IKE: OK','ike_no_response':'IKE: Sin respuesta (no concluyente)','ike_unreachable':'IKE: Fallo','openvpn_udp_response':'OpenVPN UDP: OK','udp_port_unreachable':'OpenVPN UDP: Puerto no accesible','udp_silent':'OpenVPN UDP: Sin respuesta (no concluyente)','dns_failed':'DNS: No se pudo resolver','dns_failure':'DNS: Error de resolución','dns_timeout':'DNS: Tiempo agotado','dns_no_answers':'DNS: Sin respuestas','dns_no_global_address':'Destino público no válido','private_or_reserved_destination':'Destino no público','probe_error':'No se pudo comprobar la sonda','unsupported_probe':'Tipo de VPN no compatible'}

def endpoint_health_map(vpns):
    ids=[int(v['id']) for v in vpns if v is not None]
    return health_for_vpns(db(),ids) if ids else {}

def endpoint_card_alert(health,online,admin_view=False):
    if not health:
        return ''
    if online:
        if not endpoint_admin_diagnostics_enabled():
            return ''
        if admin_view and health.get('state')=='unreachable':
            return "<div class='endpoint-probe-note' role='status'>La sonda pública no responde, pero el túnel está activo.</div>"
        return ''
    if not endpoint_public_alerts_enabled() or not public_alert_eligible(health):
        return ''
    return "<div class='endpoint-alert' role='status' aria-live='polite'><strong>Servidor VPN inaccesible</strong><span>ICMP y la sonda del protocolo han fallado durante tres ciclos consecutivos.</span></div>"

def _endpoint_time(value):
    if value is None:
        return 'Sin datos'
    try:
        return datetime.fromtimestamp(int(value)).strftime('%Y-%m-%d %H:%M:%S')
    except (TypeError,ValueError,OSError,OverflowError):
        return 'Sin datos'

def _endpoint_evidence(value, ok_label='OK', fail_label='Fallo'):
    if value is None:
        return 'Sin datos'
    return ok_label if bool(value) else fail_label

def endpoint_health_admin_markup(health):
    if not endpoint_admin_diagnostics_enabled():
        return ''
    health=health or {'state':'accessible','consecutive_failures':0,'last_checked_at':None,'last_success_at':None,'icmp_ok':None,'protocol_ok':None,'protocol_probe':None,'icmp_code':'not_checked','protocol_code':'not_checked','has_checked':False,'is_stale':False}
    state=str(health.get('state') or 'accessible')
    state_label='Sin datos' if not health.get('has_checked',health.get('last_checked_at') is not None) else ENDPOINT_STATE_LABELS.get(state,'Accesible')
    probe=str(health.get('protocol_probe') or '—')
    probe_label={'tcp':'TCP','ike':'IKE','openvpn_udp':'OpenVPN UDP'}.get(probe,probe)
    code=ENDPOINT_CODE_LABELS.get(str(health.get('protocol_code') or 'not_checked'),'Sin datos')
    if health.get('is_stale'):
        code='Sin datos recientes'
    metrics=(
        ('ICMP',_endpoint_evidence(health.get('icmp_ok'))),
        (probe_label,_endpoint_evidence(health.get('protocol_ok'))),
        ('Sonda',code),
        ('Fallos consecutivos',str(max(0,int(health.get('consecutive_failures') or 0)))),
        ('Última comprobación',_endpoint_time(health.get('last_checked_at'))),
        ('Último éxito',_endpoint_time(health.get('last_success_at'))),
    )
    meta=''.join(f"<div><dt>{html.escape(name)}</dt><dd>{html.escape(value)}</dd></div>" for name,value in metrics)
    return (f"<div class='endpoint-health' data-endpoint-state='{html.escape(state,quote=True)}'>"
            f"<div class='endpoint-health-title'><strong>{html.escape(state_label)}</strong><span class='endpoint-health-code'>{html.escape(code)}</span></div>"
            f"<dl class='endpoint-health-meta'>{meta}</dl></div>")

def endpoint_history_admin_markup(vpn_id):
    if not endpoint_admin_diagnostics_enabled():
        return ''
    intervals=history_intervals(db(),int(vpn_id),now=int(time.time()),history_hours=5)
    if not intervals:
        return "<div class='endpoint-history'><p>Sin datos</p></div>"
    segments=[]
    for item in intervals:
        state=item['state']; label=ENDPOINT_STATE_LABELS.get(state,'Accesible'); start=_endpoint_time(item['start_at']); end=_endpoint_time(item['end_at'])
        segments.append(f"<span class='endpoint-history-segment endpoint-history-{html.escape(state,quote=True)}' title='{html.escape(start+' - '+end+' · '+label,quote=True)}' aria-label='{html.escape(start+' - '+end+' · '+label,quote=True)}'></span>")
    return "<div class='endpoint-history' aria-label='Histórico de accesibilidad de las últimas 5 horas'>"+''.join(segments)+"</div>"

MONITOR_TOKEN_FILE_ENV='VPN_ENDPOINT_MONITOR_TOKEN_FILE'
MONITOR_DEFAULT_TOKEN_FILE='/run/secrets/vpn_endpoint_monitor_token'
MONITOR_TOKEN_MIN_BYTES=32
MONITOR_TOKEN_MAX_BYTES=256
MONITOR_MAX_BODY_BYTES=64*1024
MONITOR_MAX_BATCH=500

def _monitor_token_bytes():
    path=os.environ.get(MONITOR_TOKEN_FILE_ENV,'').strip() or MONITOR_DEFAULT_TOKEN_FILE
    if len(path)>4096 or '\0' in path:return None
    try:
        info=os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size>MONITOR_TOKEN_MAX_BYTES:return None
        if os.name!='nt' and info.st_mode & 0o022:return None
        with open(path,'rb') as fh:raw=fh.read(MONITOR_TOKEN_MAX_BYTES+1)
    except (OSError,ValueError):return None
    raw=raw.rstrip(bytes((13,10)))
    if not MONITOR_TOKEN_MIN_BYTES<=len(raw)<=MONITOR_TOKEN_MAX_BYTES:return None
    if any(byte<33 or byte>126 for byte in raw):return None
    return raw

def _monitor_authorized():
    header=request.headers.get('Authorization','')
    if not isinstance(header,str) or not header.startswith('Bearer '):return False
    try:provided=header[7:].encode('ascii')
    except UnicodeEncodeError:return False
    expected=_monitor_token_bytes()
    return expected is not None and hmac.compare_digest(provided,expected)

def monitor_internal(f):
    @functools.wraps(f)
    def wrapped(*args,**kwargs):
        if not endpoint_monitor_collection_enabled() or not _monitor_authorized():abort(404)
        return f(*args,**kwargs)
    return wrapped

def _row_value(row,name,default=None):
    try:return row[name]
    except (IndexError,KeyError):return default

def _monitor_openvpn_transport(row):
    profile=_row_value(row,'openvpn_profile_enc','')
    if profile:
        decoded=dec(profile)
        for raw_line in decoded.splitlines():
            parts=raw_line.strip().split()
            if len(parts)>=2 and parts[0].lower()=='proto':
                proto=parts[1].lower()
                if proto.startswith('tcp'):return 'tcp'
                if proto.startswith('udp'):return 'udp'
    return 'udp'

def _monitor_target_from_row(row, *, cycle_id=0, lease_id='pending'):
    target_generation=int(_row_value(row,'onboarding_revision',0) or 0)
    vpn_type=str(_row_value(row,'vpn_type','ssl') or 'ssl').strip().lower()
    if vpn_type not in VPN_TYPES:raise ValueError('unsupported_vpn_type')
    host=str(_row_value(row,'host','') or '').strip().lower().rstrip('.')
    if not 1<=len(host)<=253 or any(ord(ch)<33 or ord(ch)==127 for ch in host):raise ValueError('invalid_host')
    port_value=_row_value(row,'port','')
    if isinstance(port_value,bool):raise ValueError('invalid_port')
    try:port=int(str(port_value).strip(),10)
    except (TypeError,ValueError):raise ValueError('invalid_port')
    if not 1<=port<=65535:raise ValueError('invalid_port')
    transport='tcp' if vpn_type in {'ssl','pptp'} else ('udp' if vpn_type=='ipsec' else _monitor_openvpn_transport(row))
    config={'vpn_type':vpn_type,'host':host,'port':port,'transport':transport}
    target={'vpn_id':int(row['id']),'target_revision':'','target_generation':target_generation,'cycle_id':int(cycle_id),'lease_id':lease_id,'vpn_type':vpn_type,'host':host,'port':port,'transport':transport,'ike_version':'','aggressive':False,'nat_t':False}
    if vpn_type=='ipsec':
        ike=str(_row_value(row,'ike_version','ikev1') or 'ikev1').strip().lower()
        if ike not in {'ikev1','ikev2'}:raise ValueError('invalid_ike_version')
        aggressive=bool(int(_row_value(row,'aggressive',0) or 0))
        nat_t=bool(int(_row_value(row,'nat_traversal',0) or 0))
        allowed_ports = {500, 4500} if nat_t else {500}
        if port not in allowed_ports:raise ValueError('invalid_ipsec_port')
        config.update(ike_version=ike,aggressive=aggressive,nat_t=nat_t)
        target.update(ike_version=ike,aggressive=aggressive,nat_t=nat_t)
    target['target_revision']=target_revision(config)
    return target

def _monitor_expected_probe(target):
    if target['vpn_type']=='ipsec':return 'ike'
    return 'tcp' if target['transport']=='tcp' else 'openvpn_udp'

def _monitor_json(raw):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError('duplicate_json_key')
            result[key]=value
        return result
    return json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))

@app.route('/internal/vpn-endpoint-monitor/targets',methods=['GET'])
@monitor_internal
def monitor_targets():
    conn=db(); now=int(time.time()); targets=[]
    try:
        after_id=max(0,int(request.args.get('after_id','0')))
        requested_limit=max(1,min(MONITOR_MAX_BATCH,int(request.args.get('limit',MONITOR_MAX_BATCH))))
    except (TypeError,ValueError):
        return jsonify(targets=[]),400
    try:
        conn.execute('BEGIN IMMEDIATE')
        rows=conn.execute('SELECT * FROM vpns WHERE active=1 AND id>? ORDER BY id LIMIT ?', (after_id,requested_limit)).fetchall()
        for row in rows:
            try:
                generation=int(_row_value(row,'onboarding_revision',0) or 0)
                prior=conn.execute('SELECT target_generation,cycle_id FROM vpn_endpoint_monitor_leases WHERE vpn_id=?',(int(row['id']),)).fetchone()
                cycle=(int(prior['cycle_id'])+1 if prior and int(prior['target_generation'])==generation else 1)
                lease=secrets.token_urlsafe(32)
                target=_monitor_target_from_row(row,cycle_id=cycle,lease_id=lease)
                conn.execute('INSERT INTO vpn_endpoint_monitor_leases(vpn_id,target_generation,cycle_id,lease_id,issued_at) VALUES(?,?,?,?,?) ON CONFLICT(vpn_id) DO UPDATE SET target_generation=excluded.target_generation,cycle_id=excluded.cycle_id,lease_id=excluded.lease_id,issued_at=excluded.issued_at',(int(row['id']),generation,cycle,lease,now))
                targets.append(target)
            except (TypeError,ValueError,OverflowError):
                conn.rollback()
                return jsonify(targets=[]), 503
        conn.commit()
    except sqlite3.DatabaseError:
        conn.rollback(); return jsonify(targets=[]),503
    payload={'targets':targets}
    if len(rows)==requested_limit and rows:
        payload['next_after_id']=int(rows[-1]['id'])
    return jsonify(payload)

@app.route('/internal/vpn-endpoint-monitor/results',methods=['POST'])
@monitor_internal
def monitor_results():
    if request.content_length is not None and request.content_length>MONITOR_MAX_BODY_BYTES:
        return jsonify(ok=False,code='request_too_large'),413
    raw=request.get_data(cache=False)
    if len(raw)>MONITOR_MAX_BODY_BYTES:return jsonify(ok=False,code='request_too_large'),413
    try:payload=_monitor_json(raw)
    except (UnicodeDecodeError,TypeError,ValueError,json.JSONDecodeError):return jsonify(ok=False,code='invalid_request'),400
    if not isinstance(payload,dict) or set(payload)!={'results'} or not isinstance(payload['results'],list) or len(payload['results'])>MONITOR_MAX_BATCH:
        return jsonify(ok=False,code='invalid_request'),400
    normalized=[];seen=set();lease_fields={'target_generation','cycle_id','lease_id'}
    for item in payload['results']:
        try:row=validate_result(item)
        except (TypeError,ValueError):return jsonify(ok=False,code='invalid_result'),400
        supplied_lease_fields=lease_fields & set(item)
        if supplied_lease_fields and supplied_lease_fields != lease_fields:
            return jsonify(ok=False,code='invalid_result'),400
        row['_minimal_contract']=not supplied_lease_fields
        if row['vpn_id'] in seen:return jsonify(ok=False,code='duplicate_vpn_id'),400
        seen.add(row['vpn_id']);normalized.append(row)
    conn=db()
    try:
        conn.execute('BEGIN IMMEDIATE')
        placeholders=','.join('?' for _ in normalized)
        rows=conn.execute(f'SELECT * FROM vpns WHERE active=1 AND id IN ({placeholders})',tuple(seen)).fetchall()
        by_id={int(row['id']):row for row in rows}
        if len(by_id)!=len(normalized):
            conn.rollback();return jsonify(ok=False,code='target_unavailable'),409
        targets={}
        for row in normalized:
            vpn=by_id[row['vpn_id']]
            lease=conn.execute('SELECT * FROM vpn_endpoint_monitor_leases WHERE vpn_id=?',(row['vpn_id'],)).fetchone()
            generation=int(_row_value(vpn,'onboarding_revision',0) or 0)
            if lease is None:
                conn.rollback();return jsonify(ok=False,code='stale_target_generation'),409
            if row.get('_minimal_contract'):
                row['target_generation']=generation
                row['cycle_id']=int(lease['cycle_id'])
                row['lease_id']=str(lease['lease_id'])
            elif row['target_generation']!=generation:
                conn.rollback();return jsonify(ok=False,code='stale_target_generation'),409
            row.pop('_minimal_contract',None)
            if row['target_generation']!=int(lease['target_generation']) or row['cycle_id']!=int(lease['cycle_id']) or row['lease_id']!=lease['lease_id']:
                conn.rollback();return jsonify(ok=False,code='invalid_monitor_lease'),409
            try:target=_monitor_target_from_row(vpn,cycle_id=row['cycle_id'],lease_id=row['lease_id'])
            except (TypeError,ValueError,OverflowError):
                conn.rollback();return jsonify(ok=False,code='target_unavailable'),409
            targets[row['vpn_id']]=target
            if row['target_revision']!=target['target_revision']:
                conn.rollback();return jsonify(ok=False,code='stale_target_revision'),409
            if row['protocol_probe']!=_monitor_expected_probe(target):
                conn.rollback();return jsonify(ok=False,code='probe_type_mismatch'),400
        for row in normalized:apply_probe_result(conn,row,expected_revision=targets[row['vpn_id']]['target_revision'],expected_generation=targets[row['vpn_id']]['target_generation'])
        conn.commit()
    except StaleRevisionError:
        conn.rollback();return jsonify(ok=False,code='stale_target_revision'),409
    except StaleCycleError:
        conn.rollback();return jsonify(ok=False,code='stale_cycle'),409
    except ValueError:
        conn.rollback();return jsonify(ok=False,code='invalid_monitor_lease'),409
    except sqlite3.DatabaseError:
        conn.rollback();return jsonify(ok=False,code='storage_unavailable'),503
    return jsonify(ok=True,accepted=len(normalized),rejected=0)

S=r"""
:root{--canvas:#f5f5f5;--paper:#fff;--surface:#fafafa;--ink:#0a0a0a;--ink-soft:#171717;--muted:#737373;--hairline:#e5e5e5;--success:#16a34a;--danger:#e7000b;--card-radius:24px;--control-radius:18px;--shadow:0 0 0 1px rgba(23,23,23,.05),0 1px 3px rgba(0,0,0,.10),0 1px 2px -1px rgba(0,0,0,.10)}
[data-theme='dark']{--canvas:#0a0a0a;--paper:#171717;--surface:#111;--ink:#fafafa;--ink-soft:#e5e5e5;--muted:#a3a3a3;--hairline:#2f2f2f;--success:#4ade80;--danger:#ff4d55;--shadow:0 0 0 1px rgba(255,255,255,.08),0 1px 3px rgba(0,0,0,.45),0 1px 2px -1px rgba(0,0,0,.5)}
*{box-sizing:border-box}[hidden]{display:none!important}html{background:var(--canvas);color-scheme:light}html[data-theme='dark']{color-scheme:dark}body{font-family:Geist,Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--canvas);color:var(--ink);margin:0;font-size:14px;line-height:1.43;font-feature-settings:"ss01" 1,"cv11" 1;transition:background .18s ease,color .18s ease}a{color:inherit}.topbar{position:sticky;top:0;z-index:20;background:color-mix(in srgb,var(--surface) 92%,transparent);border-bottom:1px solid var(--hairline);backdrop-filter:blur(14px)}.topbar-inner{max-width:1280px;margin:auto;min-height:64px;padding:10px 24px;display:flex;align-items:center;gap:18px}.brand{display:flex;align-items:center;gap:10px;text-decoration:none;font-weight:600;letter-spacing:-.025em}.brand-mark{width:28px;height:28px;border-radius:9px;background:var(--ink);color:var(--paper);display:grid;place-items:center;font-size:11px}.nav{margin-left:auto;display:flex;align-items:center;gap:6px}.user-chip{color:var(--muted);padding:8px 10px}.wrap{max-width:1280px;margin:auto;padding:44px 24px 64px}.page-head{margin:0 0 28px}.eyebrow{margin:0 0 8px;color:var(--muted);font-size:12px;font-weight:500;letter-spacing:.05em;text-transform:uppercase}.page-head h1{font-size:36px;line-height:1.11;letter-spacing:-.025em;margin:0;font-weight:600}.page-head p{max-width:680px;color:var(--muted);font-size:16px}.card{display:block;background:var(--paper);border:1px solid var(--hairline);border-radius:var(--card-radius);box-shadow:var(--shadow);padding:20px;margin:10px 0;color:var(--ink)}a.card{text-decoration:none;transition:transform .16s ease,box-shadow .16s ease,border-color .16s ease}a.card:hover{transform:translateY(-2px);border-color:color-mix(in srgb,var(--ink) 22%,var(--hairline))}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}.plant-grid{grid-template-columns:repeat(auto-fill,minmax(300px,1fr))}.plant-card{min-height:210px;display:flex!important;flex-direction:column;justify-content:space-between}.plant-card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.plant-card h2{font-size:24px;line-height:1.33;letter-spacing:-.025em;margin:0}.plant-count{font-size:36px;line-height:1.11;letter-spacing:-.025em;font-weight:600;margin:22px 0 2px}.plant-meta{color:var(--muted);margin:0}.plant-footer{display:flex;align-items:center;justify-content:space-between;margin-top:22px}.status{display:inline-flex;align-items:center;gap:7px;border-radius:18px;padding:4px 9px;font-size:12px;font-weight:500;background:var(--canvas)}.status-dot{width:8px;height:8px;border-radius:50%;background:var(--ink)}.status[data-vpn-status='online']{color:var(--success)}.status[data-vpn-status='online'] .status-dot{background:var(--success)}.status[data-vpn-status='offline']{color:var(--danger)}.status[data-vpn-status='offline'] .status-dot{background:var(--danger)}.arrow{font-size:18px}.btn{appearance:none;background:var(--canvas);color:var(--ink);border:0;border-radius:var(--control-radius);min-height:36px;padding:8px 13px;text-decoration:none;margin:3px;display:inline-flex;align-items:center;justify-content:center;gap:7px;font:500 14px/1 inherit;cursor:pointer}.btn:hover{background:var(--hairline)}.btn.primary{background:var(--ink);color:var(--paper)}.btn.primary:hover{background:var(--ink-soft)}.btn.outline{background:transparent;box-shadow:inset 0 0 0 1px var(--hairline)}.btn.danger{color:var(--danger);background:transparent}.page-head.has-action{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:end;gap:18px}.page-head-title{min-width:0}.page-head-action{display:flex;align-items:center;justify-content:flex-end}.vpn-restart-control{display:flex;align-items:center;gap:10px}.vpn-restart-button{appearance:none;display:inline-flex;align-items:center;justify-content:center;min-width:176px;min-height:44px;padding:0 18px;border:1px solid var(--ink);border-radius:var(--control-radius);background:transparent;color:var(--ink);font:600 13px/1 inherit;letter-spacing:.055em;text-transform:uppercase;position:relative;overflow:hidden;isolation:isolate;cursor:pointer;transition:color .35s,border-color .35s,opacity .2s}.vpn-restart-button span{position:relative;z-index:2}.vpn-restart-button::after{position:absolute;content:"";inset:0;width:0;height:100%;background:var(--danger);z-index:1;transition:width .35s}.vpn-restart-button:hover:not(:disabled){color:#fff;border-color:var(--danger)}.vpn-restart-button:hover:not(:disabled)::after,.vpn-restart-button.is-loading::after{width:100%}.vpn-restart-button.is-loading{color:#fff;border-color:var(--danger);cursor:wait}.vpn-restart-button:disabled{opacity:.72}.vpn-restart-button:focus-visible{outline:3px solid color-mix(in srgb,var(--danger) 34%,transparent);outline-offset:3px}.vpn-restart-feedback{max-width:220px;color:var(--muted);font-size:12px}.vpn-restart-feedback[data-state='success']{color:var(--success)}.vpn-restart-feedback[data-state='error']{color:var(--danger)}.theme-toggle{width:40px;padding:0;font-size:17px}.breadcrumb-row{display:flex;align-items:center;gap:12px;margin-bottom:20px;flex-wrap:wrap}.breadcrumb{display:flex;gap:7px;align-items:center;margin:0;color:var(--muted)}.back-button{margin:0;white-space:nowrap}.breadcrumb a{text-decoration:none}.breadcrumb-current{color:var(--ink)}.summary-row{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 24px}.badge{display:inline-flex;align-items:center;border-radius:18px;padding:3px 9px;font-size:12px;font-weight:500;background:var(--canvas);color:var(--ink-soft)}.badge.solid{background:var(--ink-soft);color:var(--paper)}.tag-scada{--tag-fg:#1d4ed8;--tag-bg:#eff6ff;--tag-border:#bfdbfe}.tag-trackers{--tag-fg:#b45309;--tag-bg:#fffbeb;--tag-border:#fde68a}.tag-inversores{--tag-fg:#15803d;--tag-bg:#f0fdf4;--tag-border:#bbf7d0}.tag-cctv{--tag-fg:#7e22ce;--tag-bg:#faf5ff;--tag-border:#e9d5ff}.tag-set{--tag-fg:#be123c;--tag-bg:#fff1f2;--tag-border:#fecdd3}[data-theme='dark'] .tag-scada{--tag-fg:#93c5fd;--tag-bg:#172554;--tag-border:#1e40af}[data-theme='dark'] .tag-trackers{--tag-fg:#fcd34d;--tag-bg:#451a03;--tag-border:#92400e}[data-theme='dark'] .tag-inversores{--tag-fg:#86efac;--tag-bg:#052e16;--tag-border:#166534}[data-theme='dark'] .tag-cctv{--tag-fg:#d8b4fe;--tag-bg:#3b0764;--tag-border:#7e22ce}[data-theme='dark'] .tag-set{--tag-fg:#fda4af;--tag-bg:#4c0519;--tag-border:#9f1239}.tag-badge{margin:2px 4px 2px 0;color:var(--tag-fg);background:var(--tag-bg);box-shadow:inset 0 0 0 1px var(--tag-border)}.equipment-tags{min-width:150px}.tag-filter{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;background:var(--paper);border:1px solid var(--hairline);border-radius:var(--card-radius);box-shadow:var(--shadow);padding:14px 16px;margin:0 0 14px}.tag-filter-head{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}.tag-filter-options{display:flex;align-items:center;justify-content:flex-end;gap:7px;flex-wrap:wrap}.tag-filter-option{display:inline-flex;align-items:center;gap:6px;margin:0;padding:6px 10px;border:1px solid var(--tag-border);border-radius:var(--control-radius);background:color-mix(in srgb,var(--tag-bg) 68%,var(--paper));color:var(--tag-fg);font-size:12px;font-weight:600;cursor:pointer;transition:background .15s ease,box-shadow .15s ease,transform .15s ease}.tag-filter-option:hover{background:var(--tag-bg);transform:translateY(-1px)}.tag-filter-option.is-active{background:var(--tag-bg);box-shadow:inset 0 0 0 1px var(--tag-fg)}.tag-filter-option input{width:auto;margin:0;accent-color:var(--tag-fg)}.tag-filter-clear{min-height:30px;padding:6px 10px;font-size:12px}.tag-filter-clear:disabled{opacity:.42;cursor:default}.tag-filter-empty{padding:26px;text-align:center}.tag-picker{border:1px solid var(--hairline);border-radius:var(--control-radius);padding:14px 16px;margin:16px 0}.tag-picker legend{font-weight:600;padding:0 6px}.tag-picker p{margin:0 0 8px}.tag-options{display:flex;flex-wrap:wrap;gap:8px}.tag-option{display:inline-flex;align-items:center;gap:7px;margin:0;padding:7px 10px;border:1px solid var(--tag-border);border-radius:var(--control-radius);background:var(--tag-bg);color:var(--tag-fg);cursor:pointer}.tag-option input{width:auto;margin:0;accent-color:var(--tag-fg)}.table-card{padding:0;overflow:hidden}.table-scroll{overflow-x:auto}table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid var(--hairline);padding:14px 16px;text-align:left;vertical-align:middle}th{background:var(--surface);color:var(--muted);font-size:12px;font-weight:500;letter-spacing:.05em;text-transform:uppercase;white-space:nowrap}tr:last-child td{border-bottom:0}tbody tr:hover{background:color-mix(in srgb,var(--canvas) 65%,transparent)}.sort-button{appearance:none;border:0;background:transparent;color:inherit;font:inherit;letter-spacing:inherit;text-transform:inherit;padding:0;cursor:pointer;display:inline-flex;align-items:center;gap:6px}.sort-button::after{content:"↕";opacity:.45}.sort-button[data-direction='asc']::after{content:"↑";opacity:1}.sort-button[data-direction='desc']::after{content:"↓";opacity:1}.equipment-name{font-weight:600}.url{font-family:"Geist Mono",ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--muted);font-size:13px}.muted{color:var(--muted)}.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px}.vpn-form h3{margin-top:28px;border-bottom:1px solid var(--hairline);padding-bottom:9px}.error{border-color:var(--danger);color:var(--danger)}input,select,textarea{width:100%;padding:10px 12px;background:var(--canvas);color:var(--ink);border:1px solid transparent;border-radius:var(--control-radius);font:inherit;outline:0}input:focus,select:focus,textarea:focus{background:var(--paper);border-color:var(--hairline);box-shadow:0 0 0 3px color-mix(in srgb,var(--ink) 8%,transparent)}label{display:block;margin-top:10px;font-weight:500}.flash{margin-bottom:16px}.empty{text-align:center;padding:40px}.actions{white-space:nowrap}.desktop-only{display:table-cell}.endpoint-health{min-width:250px;display:grid;gap:8px;line-height:1.35}.endpoint-health-title{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.endpoint-health-title strong{font-size:13px;line-height:1.3}.endpoint-health-code{display:inline-flex;align-items:center;border:1px solid var(--hairline);border-radius:999px;padding:3px 8px;color:var(--muted);font-size:11px;line-height:1.25}.endpoint-health-meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px 14px;margin:0}.endpoint-health-meta>div{display:grid;gap:1px;min-width:0}.endpoint-health-meta dt{color:var(--muted);font-size:11px;line-height:1.25}.endpoint-health-meta dd{margin:0;color:var(--ink);font-size:12px;line-height:1.3;white-space:nowrap;font-variant-numeric:tabular-nums}.endpoint-health[data-endpoint-state='accessible'] .endpoint-health-title strong{color:var(--success)}.endpoint-health[data-endpoint-state='unreachable'] .endpoint-health-title strong{color:var(--danger)}
@media(max-width:760px){.page-head.has-action{grid-template-columns:1fr;align-items:start}.page-head-action{justify-content:flex-start}.vpn-restart-control{align-items:flex-start;flex-direction:column}.vpn-restart-button{min-width:164px}.topbar-inner{padding:9px 14px}.user-chip{display:none}.wrap{padding:28px 14px 48px}.page-head h1{font-size:30px}.plant-grid{grid-template-columns:1fr}.desktop-only{display:none}.endpoint-health{min-width:220px}.endpoint-health-meta{grid-template-columns:1fr}th,td{padding:12px}.brand-text{display:none}}
"""
THEME_SCRIPT=r"""<script>(function(){try{var saved=localStorage.getItem('theme');var preferred=window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';document.documentElement.dataset.theme=saved||preferred}catch(e){}})();function syncThemeButton(){var b=document.getElementById('theme-toggle');if(!b)return;var dark=document.documentElement.dataset.theme==='dark';b.textContent=dark?'☀':'☾';b.setAttribute('aria-label',dark?'Activar modo claro':'Activar modo nocturno');b.title=b.getAttribute('aria-label')}function toggleTheme(){var next=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=next;localStorage.setItem('theme',next);syncThemeButton()}document.addEventListener('DOMContentLoaded',syncThemeButton);</script>"""
SORT_SCRIPT=r"""<script>function sortEquipmentTable(button){var table=document.getElementById('equipment-table'),head=button.closest('th'),index=Array.prototype.indexOf.call(head.parentNode.children,head),body=table.tBodies[0],rows=Array.from(body.rows),direction=button.dataset.direction==='asc'?'desc':'asc';table.querySelectorAll('.sort-button').forEach(function(x){if(x!==button)delete x.dataset.direction});button.dataset.direction=direction;rows.sort(function(a,b){var av=a.cells[index].dataset.sortValue||a.cells[index].textContent.trim(),bv=b.cells[index].dataset.sortValue||b.cells[index].textContent.trim();var result=av.localeCompare(bv,'es',{numeric:true,sensitivity:'base'});return direction==='asc'?result:-result});rows.forEach(function(row){body.appendChild(row)});}</script>"""
TAG_FILTER_SCRIPT=r"""<script>function filterEquipmentTags(input){var root=input.closest('[data-tag-filter]'),table=document.getElementById(root.dataset.tableId),selected=Array.from(root.querySelectorAll('[data-filter-tag]:checked')).map(x=>x.dataset.filterTag.toLowerCase()),rows=Array.from(table.tBodies[0].rows),visibleCount=0;root.querySelectorAll('.tag-filter-option').forEach(x=>x.classList.toggle('is-active',x.querySelector('input').checked));rows.forEach(row=>{var rowTags=(row.dataset.tags||'').split(',').filter(Boolean),visible=!selected.length||selected.some(tag=>rowTags.includes(tag));row.hidden=!visible;if(visible)visibleCount++});var count=root.querySelector('[data-filter-count]');count.textContent=selected.length?visibleCount+' de '+rows.length+' equipos':rows.length+(rows.length===1?' equipo':' equipos');root.querySelector('[data-filter-clear]').disabled=!selected.length;var empty=document.getElementById(root.dataset.emptyId||'equipment-filter-empty');if(empty)empty.hidden=visibleCount!==0}function clearEquipmentTagFilters(button){var root=button.closest('[data-tag-filter]');root.querySelectorAll('[data-filter-tag]').forEach(x=>x.checked=false);var first=root.querySelector('[data-filter-tag]');if(first)filterEquipmentTags(first)}document.addEventListener('DOMContentLoaded',function(){document.querySelectorAll('[data-tag-filter]').forEach(function(root){var first=root.querySelector('[data-filter-tag]');if(first)filterEquipmentTags(first)})});</script>"""
VPN_RESTART_SCRIPT=r"""<script>async function restartPlantVpn(button){if(button.disabled)return;if(!confirm('La conexión de esta planta se interrumpirá temporalmente. ¿Reiniciar su VPN ahora?'))return;var feedback=document.getElementById('vpn-restart-feedback');button.disabled=true;button.classList.add('is-loading');button.setAttribute('aria-busy','true');button.querySelector('span').textContent='Reiniciando…';feedback.dataset.state='loading';feedback.textContent='Reiniciando la VPN exacta…';try{var body=new URLSearchParams({_csrf:button.dataset.restartCsrf});var response=await fetch(button.dataset.restartUrl,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8','Accept':'application/json'},body:body.toString()});var data=await response.json().catch(function(){return {ok:false,message:'Respuesta no válida del servidor.'}});if(!response.ok||!data.ok)throw new Error(data.message||'No se pudo reiniciar la VPN.');feedback.dataset.state='success';feedback.textContent=data.message;button.querySelector('span').textContent='VPN reiniciada';setTimeout(function(){location.reload()},2200)}catch(error){feedback.dataset.state='error';feedback.textContent=error.message;button.disabled=false;button.classList.remove('is-loading');button.removeAttribute('aria-busy');button.querySelector('span').textContent='Reiniciar VPN'}}</script>"""
def page(t,b,head_action=''):
    def _csrf_form(m):
        block=m.group(0)
        if 'name=_csrf' in block or 'name="_csrf"' in block:return block
        return block.replace('>',f"><input type=hidden name=_csrf value='{h(csrf_token())}'>",1)
    b=re.sub(r'<form\b(?=[^>]*method\s*=\s*["\']?post\b)[^>]*>.*?</form>',_csrf_form,b,flags=re.I|re.S)
    u=me();nav=''
    if u:nav=(f"<span class='user-chip'>{html.escape(u['username'])}</span><a class='btn' href='/'>Panel</a>"+("<a class='btn' href='/admin'>Admin</a>" if u['role']=='admin' else '')+"<a class='btn' href='/logout'>Salir</a>")
    flashes=''.join("<div class='card flash'>"+html.escape(x)+"</div>" for x in get_flashed_messages())
    head_class='page-head has-action' if head_action else 'page-head';head=f"<div class='{head_class}'><div class='page-head-title'><p class='eyebrow'>Infraestructura remota</p><h1>{t}</h1></div>"+(f"<div class='page-head-action'>{head_action}</div>" if head_action else '')+"</div>"
    return ("<!doctype html><html lang='es'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"+THEME_SCRIPT+f"<style>{S}</style><title>{html.escape(t)}</title></head><body><header class='topbar'><div class='topbar-inner'><a class='brand' href='/'><span class='brand-mark'>PV</span><span class='brand-text'>Accesos de planta</span></a>"+f"<nav class='nav'>{nav}<button class='btn outline theme-toggle' id='theme-toggle' type='button' onclick='toggleTheme()' aria-label='Activar modo nocturno'>☾</button></nav></div></header>"+f"<main class='wrap'>{head}{flashes}{b}</main></body></html>")

@app.before_request
def protect_admin_csrf():
    if os.environ.get('PANEL_TEST_ALLOW_MISSING_CSRF')=='1':return
    if request.method in {'POST','PUT','PATCH','DELETE'} and request.path.startswith('/admin/'):
        try:verify_onboarding_csrf(request.form)
        except ValueError as e:abort(400,description=str(e))

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        u=db().execute('SELECT * FROM users WHERE username=? AND active=1',(request.form['username'],)).fetchone()
        if u and check_password_hash(u['password_hash'],request.form['password']): session['uid']=u['id']; return redirect('/')
        flash('Login incorrecto')
    return page('Login',"<form class=card method=post><label>Usuario</label><input name=username><label>Password</label><input name=password type=password><button class='btn primary'>Entrar</button></form>")
@app.route('/logout')
def logout(): session.clear(); return redirect('/login')
def accessible_equipment(u):
    if u['role']=='admin':return db().execute('SELECT * FROM equipment WHERE active=1 ORDER BY plant,name').fetchall()
    return db().execute('SELECT DISTINCT e.* FROM equipment e LEFT JOIN permissions p ON p.equipment_id=e.id LEFT JOIN plant_permissions pp ON pp.plant=e.plant WHERE e.active=1 AND (p.user_id=? OR pp.user_id=?) ORDER BY e.plant,e.name',(u['id'],u['id'])).fetchall()
def grouped_accessible_equipment(u):
    groups={}
    for row in accessible_equipment(u):
        label=normalize_plant_name(row['plant']);key=plant_key(label)
        if key:groups.setdefault(key,{'plant':label,'items':[]})['items'].append(row)
    return sorted(groups.values(),key=lambda x:x['plant'].casefold())
@app.route('/')
@need
def idx():
    groups=grouped_accessible_equipment(me())
    if not groups:return page('Panel de accesos',"<div class='card empty'><h2>Sin accesos asignados</h2><p class='muted'>No tiene equipos o plantas disponibles.</p></div>")
    total=sum(len(g['items']) for g in groups);b=f"<p class='muted'>Seleccione una planta para consultar y abrir sus equipos autorizados.</p><div class='summary-row'><span class='badge solid'>{len(groups)} plantas</span><span class='badge'>{total} equipos</span></div><div class='grid plant-grid'>"
    for group in groups:
        plant=group['plant'];items=group['items'];vpn=vpn_for_plant(plant);online=False
        if vpn:
            try:online=vpn_runtime(vpn)[0]
            except Exception:online=False
        status='online' if online else 'offline';web=sum(1 for e in items if e['kind']=='WEB');rdp=sum(1 for e in items if e['kind']=='RDP');vnc=sum(1 for e in items if e['kind']=='VNC');href='/plant/'+quote(plant,safe='');equipment_copy='equipo disponible' if len(items)==1 else 'equipos disponibles'
        health=endpoint_health_map([vpn])[int(vpn['id'])] if vpn else None
        alert=endpoint_card_alert(health,online,admin_view=me()['role']=='admin')
        b+=(f"<a class='card plant-card' href='{href}'><div><div class='plant-card-head'><h2>{html.escape(plant)}</h2><span class='status' data-vpn-status='{status}'><span class='status-dot'></span>VPN {status}</span></div>{alert}<div class='plant-count'>{len(items)}</div><p class='plant-meta'>{equipment_copy}</p></div><div class='plant-footer'><span class='muted'>WEB {web} · RDP {rdp} · VNC {vnc}</span><span class='arrow'>→</span></div></a>")
    return page('Panel de accesos',b+'</div>')
@app.route('/plant/<path:plant>')
@need
def plant_access(plant):
    requested=plant_key(plant);group=next((g for g in grouped_accessible_equipment(me()) if plant_key(g['plant'])==requested),None)
    if not group:abort(404)
    canonical=group['plant'];items=group['items'];vpn=vpn_for_plant(canonical);online=False
    if vpn:
        try:online=vpn_runtime(vpn)[0]
        except Exception:online=False
    status='online' if online else 'offline';equipment_label='equipo' if len(items)==1 else 'equipos';health=endpoint_health_map([vpn])[int(vpn['id'])] if vpn else None;back="<div class='breadcrumb-row'><a class='btn outline back-button' href='/' aria-label='Volver al panel'>← Atrás</a><div class='breadcrumb'><a href='/'>Panel de accesos</a><span>›</span><span class='breadcrumb-current'>"+html.escape(canonical)+"</span></div></div>"
    plant_url=quote(canonical,safe='');head_action=(f"<div class='vpn-restart-control'><button class='vpn-restart-button' type='button' data-restart-url='/plant/{plant_url}/vpn/restart' data-restart-csrf='{h(csrf_token())}' onclick='restartPlantVpn(this)'><span>Reiniciar VPN</span></button><span class='vpn-restart-feedback' id='vpn-restart-feedback' role='status' aria-live='polite'></span></div>" if vpn else '')
    b=(back+endpoint_card_alert(health,online,admin_view=me()['role']=='admin')+f"<div class='summary-row'><span class='status' data-vpn-status='{status}'><span class='status-dot'></span>VPN {status}</span><span class='badge'>{len(items)} {equipment_label}</span></div>"+equipment_tag_filter_controls()+"<div class='card table-card'><div class='table-scroll'><table id='equipment-table'><thead><tr>"+"<th><button class='sort-button' data-sort-key='name' onclick='sortEquipmentTable(this)'>Nombre</button></th><th><button class='sort-button' data-sort-key='kind' onclick='sortEquipmentTable(this)'>Tipo</button></th><th><button class='sort-button' data-sort-key='tags' onclick='sortEquipmentTable(this)'>Tags</button></th><th><button class='sort-button' data-sort-key='ip' onclick='sortEquipmentTable(this)'>IP real</button></th><th><button class='sort-button' data-sort-key='port' onclick='sortEquipmentTable(this)'>Puerto</button></th><th class='desktop-only'><button class='sort-button' data-sort-key='description' onclick='sortEquipmentTable(this)'>Descripción</button></th><th>Acceso</th></tr></thead><tbody>")
    for e in items:
        name=html.escape(e['name']);kind=html.escape(e['kind']);ip=html.escape(e['real_ip']);port=html.escape(str(e['real_port']));desc=html.escape(e['description'] or '—')
        tags=equipment_tag_names(db(),e['id']);tag_sort='|'.join(tag.casefold() for tag in tags);tag_filter=','.join(tag.casefold() for tag in tags);tag_badges=equipment_tag_badges(tags)
        if e['kind']=='RDP': access=f"<a class='btn primary' href='/equipment/{e['id']}/rdp' target='_blank' rel='noopener'>Abrir RDP</a>"
        elif e['kind']=='VNC': access=f"<a class='btn primary' href='/equipment/{e['id']}/vnc' target='_blank' rel='noopener'>Abrir VNC</a>"
        else: access=f"<a class='btn primary' href='{html.escape(e['public_url'] or '',quote=True)}' target='_blank' rel='noopener'>Abrir WEB</a>"
        b+=(f"<tr data-tags='{html.escape(tag_filter,quote=True)}'><td class='equipment-name' data-sort-value='{html.escape((e['name'] or '').casefold(),quote=True)}'>{name}</td><td data-sort-value='{html.escape((e['kind'] or '').casefold(),quote=True)}'><span class='badge'>{kind}</span></td><td class='equipment-tags' data-sort-value='{html.escape(tag_sort,quote=True)}'>{tag_badges}</td><td class='url' data-sort-value='{html.escape(e['real_ip'] or '',quote=True)}'>{ip}</td><td class='url' data-sort-value='{port}'>{port}</td><td class='desktop-only' data-sort-value='{html.escape((e['description'] or '').casefold(),quote=True)}'>{desc}</td><td class='actions'>{access}</td></tr>")
    return page('Equipos · '+html.escape(canonical),b+"</tbody></table></div></div><div id='equipment-filter-empty' class='card tag-filter-empty' hidden>No hay equipos con los tags seleccionados.</div>"+SORT_SCRIPT+TAG_FILTER_SCRIPT+VPN_RESTART_SCRIPT,head_action=head_action)

class VpnRestartError(RuntimeError):
 def __init__(self,message,status):super().__init__(message);self.status=status
def restart_exact_vpn(v):
 sl=v['slug'];name='vpn-'+sl;rc,out=_inspect_exact(name,'{{.Id}}|{{index .Config.Labels "com.docker.compose.service"}}|{{.Image}}|{{index .Config.Labels "plantas.vpn.owner"}}|{{index .Config.Labels "plantas.vpn.revision"}}')
 if rc!=0:raise VpnRestartError('No se pudo validar la VPN exacta.',409)
 cid,service,image,owner_got,revision_got=(out.split('|')+['','','','',''])[:5];expected_image=(v['runtime_image_ref'] or '') if 'runtime_image_ref' in v.keys() else '';owner_expected=str(v['generation_owner'] or '') if 'generation_owner' in v.keys() else '';revision_expected=str(int(v['onboarding_revision'] or 0)) if 'onboarding_revision' in v.keys() else '0'
 if service!=name or (expected_image and image!=expected_image) or (owner_expected and (owner_got!=owner_expected or revision_got!=revision_expected)):raise VpnRestartError('La identidad de la VPN no coincide con la planta.',409)
 r=subprocess.run(['docker','restart',name],text=True,capture_output=True,timeout=90)
 if r.returncode!=0:raise VpnRestartError('Docker no pudo reiniciar la VPN.',502)
 rc2,out2=_inspect_exact(name,'{{.Id}}')
 if rc2!=0 or out2.strip()!=cid:raise VpnRestartError('No se pudo verificar el reinicio de la VPN.',502)
 return cid
class VpnPauseError(RuntimeError):
 def __init__(self,message,status):super().__init__(message);self.status=status
def pause_exact_vpn(v):
 name='vpn-'+v['slug']
 try:r=subprocess.run(['docker','pause',name],text=True,capture_output=True,timeout=30)
 except subprocess.TimeoutExpired:raise VpnPauseError('Docker no respondió al pausar la VPN.',504)
 except OSError:raise VpnPauseError('No se pudo ejecutar Docker para pausar la VPN.',502)
 if r.returncode!=0:raise VpnPauseError('Docker no pudo pausar la VPN.',502)
@app.route('/plant/<path:plant>/vpn/restart',methods=['POST'])
@need
def plant_vpn_restart(plant):
 requested=plant_key(plant);group=next((g for g in grouped_accessible_equipment(me()) if plant_key(g['plant'])==requested),None)
 if not group:abort(404)
 try:verify_onboarding_csrf(request.form)
 except ValueError:return jsonify(ok=False,message='La sesión ha caducado. Recargue la página.'),400
 v=vpn_for_plant(group['plant'])
 if not v:return jsonify(ok=False,message='Esta planta no tiene una VPN activa.'),409
 try:
  with vpn_slug_lock(v['slug'],blocking=False):restart_exact_vpn(v)
 except BlockingIOError:return jsonify(ok=False,message='Ya hay una operación VPN en curso para esta planta.'),409
 except VpnRestartError as e:return jsonify(ok=False,message=str(e)),e.status
 return jsonify(ok=True,message='VPN reiniciada. El túnel se está restableciendo.')

@app.route('/admin')
@admin
def adm(): return page('Admin',"<div class=grid><a class=card href=/admin/vpns><h2>VPNs</h2></a><a class=card href=/admin/users><h2>Usuarios</h2></a><a class=card href=/admin/equipment><h2>Equipos</h2></a></div>")


def clean_vpn_error(s):
    s=re.sub(r'(password|psk|xauth|secret)\s*[=:].*',r'\1=REDACTED',s or '',flags=re.I)
    lines=[x.strip() for x in s.splitlines() if x.strip()]
    keep=[x for x in lines if re.search(r'ERROR|failed|INVALID|AUTH|certificate|timed out|no connection|terminated',x,re.I)]
    return ' | '.join(keep[-3:])[-420:] or 'Sin detalle de error disponible todavía.'
def extract_peer_id(text):
    # Only identity types that can be represented unambiguously in Libreswan.
    matches=re.findall(r"Peer ID is (ID_[A-Z0-9_]+): '([^'\r\n]+)'",text or '')
    for kind,value in reversed(matches):
        value=value.strip()
        if kind in {'ID_IPV4_ADDR','ID_IPV6_ADDR'}:
            try:
                import ipaddress
                ip=ipaddress.ip_address(value)
                if (kind=='ID_IPV4_ADDR') != (ip.version==4): continue
                return str(ip),kind
            except ValueError: continue
        if kind=='ID_FQDN' and len(value)<=253 and re.fullmatch(r'[A-Za-z0-9.-]+',value) and '..' not in value and not value.startswith('.') and not value.endswith('.'):
            return '@'+value,kind
        if kind=='ID_USER_FQDN' and len(value)<=255 and re.fullmatch(r'[A-Za-z0-9_.+%~-]+@[A-Za-z0-9.-]+',value):
            return value,kind
    return None

def detect_peer_id(container,attempts=8):
    for _ in range(attempts):
        logs=subprocess.run(['docker','logs','--tail','160',container],text=True,capture_output=True,timeout=12)
        found=extract_peer_id(logs.stdout+'\n'+logs.stderr)
        if found: return found
        time.sleep(1)
    return None

def wait_vpn_runtime(v,timeout=24):
    end=time.time()+timeout; last=(False,'','La negociación VPN no terminó dentro del tiempo de espera.')
    while time.time()<end:
        last=vpn_runtime(v)
        if last[0]: return last
        time.sleep(2)
    return last

def vpn_runtime(v):
    name='vpn-'+v['slug']
    ins=subprocess.run(['docker','inspect','-f','{{.State.Status}}',name],text=True,capture_output=True,timeout=12)
    if ins.returncode: return False,'','Contenedor no creado.'
    state=ins.stdout.strip().split('|')[0]
    if state=='paused': return False,'','VPN pausada.'
    logs=subprocess.run(['docker','logs','--tail','100',name],text=True,capture_output=True,timeout=12)
    text=(logs.stdout+'\n'+logs.stderr)
    vpn_type=v['vpn_type'] or 'ssl'
    if vpn_type in {'ssl','pptp'}:
        r=subprocess.run(['docker','exec',name,'sh','-lc','ip -4 -o addr show dev ppp0 2>/dev/null || true'],text=True,capture_output=True,timeout=12)
        m=re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)',r.stdout)
        if vpn_type=='pptp':
            route=subprocess.run(['docker','exec',name,'sh','-lc','ip route show default 2>/dev/null || true'],text=True,capture_output=True,timeout=12)
            if state=='running' and m and re.search(r'^default\s+.*\bdev\s+ppp0\b',route.stdout,re.M): return True,m.group(1),''
            text+='\n'+route.stdout
        elif state=='running' and m: return True,m.group(1),' '
    elif vpn_type=='openvpn':
        r=subprocess.run(['docker','exec',name,'sh','-lc',"ip -4 -o addr show 2>/dev/null | awk '$2 ~ /^tun/ {print; exit}'"],text=True,capture_output=True,timeout=12)
        m=re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)',r.stdout)
        p=subprocess.run(['docker','exec',name,'sh','-lc','pgrep -x openvpn >/dev/null 2>&1'],text=True,capture_output=True,timeout=12)
        if state=='running' and m and p.returncode==0: return True,m.group(1),''
        text+='\n'+r.stdout
    else:
        st=subprocess.run(['docker','exec',name,'sh','-lc','ipsec status 2>/dev/null || true'],text=True,capture_output=True,timeout=12)
        m=re.search(r'(\d+\.\d+\.\d+\.\d+)/32\s*===',st.stdout)
        if state=='running' and re.search(r'STATE_QUICK_I2|IPsec SAs: total\(1\)|ESTABLISHED|INSTALLED',st.stdout): return True,(m.group(1) if m else ''),''
        text+='\n'+st.stdout
        if 'half-open(' in st.stdout or 'STATE_AGGR' in st.stdout:
            return False,'','IPsec: fase 1 IKE incompleta; revisar Remote ID, PSK y parámetros de fase 1. '+clean_vpn_error(text)
    return False,'',clean_vpn_error(text)
def gen_access_vpn(v, sl):
    if v['vpn_type']=='pptp': return gen_pptp(v,sl)
    if v['vpn_type']=='openvpn': return gen_openvpn(v,sl)
    raise ValueError('Tipo de VPN de acceso no válido.')

def apply_vpn(v):
    sl=v['slug']; os.makedirs(f'{BASE}/configs/{sl}',exist_ok=True); os.makedirs(f'{BASE}/sites/{sl}',exist_ok=True)
    ensure_haproxy(sl,v['plant'])
    vpn_type=v['vpn_type'] or 'ssl'; is_ipsec=vpn_type=='ipsec'; is_access=vpn_type in {'pptp','openvpn'}
    auto_remote=is_ipsec and (v['ike_version'] or 'ikev1')=='ikev1' and (v['ipsec_engine'] or 'libreswan')=='libreswan' and int(v['aggressive'] or 0)==1 and not (v['remote_id'] or '').strip()
    try:
        if is_ipsec: gen_ipsec(v,sl)
        elif is_access: gen_access_vpn(v,sl)
        else: gen_ssl(v,sl)
    except ValueError as e:
        return False,'',('Configuración IPsec no válida: ' if is_ipsec else 'Configuración VPN no válida: ')+str(e)
    publish_plant(v['plant'])
    if auto_remote:
        found=detect_peer_id(f'vpn-{sl}')
        if not found:
            return False,'','No se pudo detectar el Remote ID anunciado por el FortiGate. Revise alcance UDP 500/4500 y la propuesta IKE.'
        candidate,kind=found
        trial=dict(v); trial['remote_id']=candidate
        gen_ipsec(trial,sl); publish_plant(v['plant'])
        result=wait_vpn_runtime(trial,24)
        if result[0]:
            db().execute('UPDATE vpns SET remote_id=? WHERE id=?',(candidate,v['id'])); db().commit()
            return result
        return False,'',f'Remote ID detectado como {candidate} ({kind}), pero no se guardó porque el túnel no completó autenticación y SA IPsec. '+result[2]
    if vpn_type=='ssl' and not dec(v['trusted_cert_enc']) and int(v.get('accept_gateway_certificate') or 0):
        time.sleep(4)
        logs=subprocess.run(['docker','logs','--tail','80',f'vpn-{sl}'],text=True,capture_output=True,timeout=12)
        m=re.search(r'trusted-cert\s*=\s*([a-f0-9]{{64}})',logs.stdout+'\n'+logs.stderr,re.I)
        if m:
            db().execute('UPDATE vpns SET trusted_cert_enc=? WHERE id=?',(enc(m.group(1).lower()),v['id'])); db().commit()
            v=db().execute('SELECT * FROM vpns WHERE id=?',(v['id'],)).fetchone()
            gen_ssl(v,sl); publish_plant(v['plant'])
    current=db().execute('SELECT * FROM vpns WHERE id=?',(v['id'],)).fetchone()
    return wait_vpn_runtime(current,24)

@app.route('/admin/vpns')
@admin
def vpns():
    rows=db().execute('SELECT * FROM vpns ORDER BY plant').fetchall();b="<a class='btn primary' href=/admin/vpns/new>Añadir VPN</a><table><tr><th>Planta</th><th>Tipo</th><th>Gateway</th><th>Estado</th><th>IP VPN</th><th></th></tr>"
    health_by_id=endpoint_health_map(rows)
    b=b.replace('<th>Estado</th>', '<th>Estado</th><th>Endpoint público</th>', 1)
    for v in rows:
        kind=v['vpn_type'] or 'ssl'
        if kind=='ssl':profile='SSL · openfortivpn'
        elif kind=='openvpn':profile='OpenVPN'
        elif kind=='pptp':profile='PPTP'
        elif (v['ike_version'] or 'ikev1')=='ikev2':profile='IPsec · IKEv2 · EAP-MSCHAPv2 + PSK · strongSwan'
        else:profile='IPsec · IKEv1 · PSK + XAuth · '+('strongSwan' if (v['ipsec_engine'] or 'libreswan')=='strongswan' else 'Libreswan')
        active=int(v['active'] or 0)==1
        if active:online,ip,err=vpn_runtime(v);icon='🟢' if online else '🔴';status='Online' if online else 'Error';detail='Online' if online else err
        else:online=False;ip='';icon='🟠';status=v['onboarding_state'] or 'draft';detail=v['validation_detail'] or 'Pendiente de validación.'
        actions=f"<a class=btn href=/admin/vpns/{v['id']}/edit>Editar</a>"
        if active:
            if err=='VPN pausada.':icon='🟠';status='Pausada'
            actions+=f"<form method=post action=/admin/vpns/{v['id']}/reload style='display:inline'><input type=hidden name=_csrf value='{h(csrf_token())}'><button class=btn>⟳ Reiniciar VPN exacta</button></form>"
            actions+=f"<form method=post action=/admin/vpns/{v['id']}/pause style='display:inline'><input type=hidden name=_csrf value='{h(csrf_token())}'><button class='btn danger' onclick='return confirm(&quot;¿Pausar el contenedor Docker de esta VPN? Se interrumpirán sus accesos WEB/RDP.&quot;)'>Pausar VPN</button></form>"
        elif v['onboarding_state']=='verified_pending_activation':actions+=f"<form method=post action=/admin/vpns/{v['id']}/activate style='display:inline'><input type=hidden name=_csrf value='{h(csrf_token())}'><button class='btn primary'>Activar tras revalidar</button></form>"
        actions+=f"<form method=post action=/admin/vpns/{v['id']}/delete style='display:inline'><input type=hidden name=_csrf value='{h(csrf_token())}'><button class=btn onclick='return confirm(&quot;Eliminar VPN, equipos, permisos, configuración y contenedor asociados?&quot;)'>Eliminar VPN</button></form>"
        normalized_runtime_detail='Online' if online else ('Pausada' if status=='Pausada' else 'VPN no disponible')
        display_detail = detail if not active else normalized_runtime_detail
        b+=f"<tr><td>{h(v['plant'])}</td><td>{h(profile)}</td><td>{h(v['host'])}:{h(v['port'] or '')}</td><td title='{h(normalized_runtime_detail)}'>{icon} {h(status)}<br><span class='muted'>{h(display_detail)}</span></td><td>{endpoint_health_admin_markup(health_by_id.get(int(v['id'])))}</td><td class=url>{h(ip or '-')}</td><td>{actions}</td></tr>"
    b+='</table><p class=muted>Los borradores se validan de forma aislada. Solo pasan a activos tras validar control, datos, rutas y destino interno.</p>';return page('VPNs',b)

@app.route('/admin/vpns/<int:i>/activate',methods=['POST'])
@admin
@vpn_mutation_lock
def vpn_activate(i):
    try:verify_onboarding_csrf(request.form)
    except ValueError:abort(400)
    c=db();v=c.execute('select active,onboarding_state from vpns where id=?',(i,)).fetchone()
    if not v:abort(404)
    if int(v['active'] or 0) or v['onboarding_state']!='verified_pending_activation':abort(409)
    cur=c.execute("update vpns set auto_activate=1,onboarding_state='installed',validation_stage='activation',validation_code='manual_activation_requested',validation_detail='Activación administrativa solicitada; se repetirán todos los gates.',next_retry_at=0,reconcile_lock_token='',reconcile_lock_until=null where id=? and active=0 and onboarding_state='verified_pending_activation'",(i,));c.commit()
    if cur.rowcount!=1:abort(409)
    flash('Activación solicitada. La VPN seguirá inactiva hasta repetir todos los gates.');return redirect('/admin/vpns')

@app.route('/admin/vpns/<int:i>/reload',methods=['POST'])
@admin
@vpn_mutation_lock
def vpn_reload(i):
    try:verify_onboarding_csrf(request.form)
    except ValueError:abort(400)
    v=db().execute('SELECT * FROM vpns WHERE id=?',(i,)).fetchone()
    if not v:abort(404)
    if not int(v['active'] or 0):abort(409)
    try:restart_exact_vpn(v)
    except VpnRestartError as e:abort(e.status,description=str(e))
    flash('VPN exacta reiniciada; no se regeneraron archivos ni se tocaron otros slugs.');return redirect('/admin/vpns')

@app.route('/admin/vpns/<int:i>/pause',methods=['POST'])
@admin
@vpn_mutation_lock
def vpn_pause(i):
    try:verify_onboarding_csrf(request.form)
    except ValueError:abort(400)
    v=db().execute('SELECT * FROM vpns WHERE id=?',(i,)).fetchone()
    if not v:abort(404)
    if not int(v['active'] or 0):abort(409)
    try:pause_exact_vpn(v)
    except VpnPauseError as e:abort(e.status,description=str(e))
    flash('VPN pausada correctamente. Recargar VPN exacta la reactivará.')
    return redirect('/admin/vpns')

@app.route('/admin/vpns/<int:i>/delete',methods=['POST'])
@admin
@vpn_mutation_lock
def vpn_delete(i):
    try:verify_onboarding_csrf(request.form)
    except ValueError:abort(400)
    c=db();v=c.execute('select id from vpns where id=?',(i,)).fetchone()
    if not v:abort(404)
    cur=c.execute("update vpns set active=0,onboarding_state='deleting',validation_stage='cleanup',validation_code='deleting',validation_detail='Eliminación aislada pendiente del reconciliador.',next_retry_at=0,reconcile_lock_token='',reconcile_lock_until=null where id=?",(i,));c.commit()
    if cur.rowcount!=1:abort(409)
    flash('Eliminación aislada programada; el worker verificará ownership antes de retirar recursos.');return redirect('/admin/vpns')

def slug(s): return re.sub('[^a-z0-9-]+','-',s.lower()).strip('-')
def h(x): return html.escape(str(x or ''),quote=True)
def csrf_token():
    if not has_request_context(): return ''
    if not session.get('_onboarding_csrf'): session['_onboarding_csrf']=secrets.token_urlsafe(32)
    return session['_onboarding_csrf']
def verify_onboarding_csrf(form):
    supplied=str(form.get('_csrf') or ''); expected=str(session.get('_onboarding_csrf') or '')
    if not supplied or not expected or not secrets.compare_digest(supplied,expected): raise ValueError('La sesión del formulario ha caducado. Recargue la página.')
def opts(items,current): return ''.join(f"<option value='{h(k)}' {'selected' if str(k)==str(current) else ''}>{h(label)}</option>" for k,label in items)
def csv_values(value):
    raw=value if isinstance(value,(list,tuple)) else re.split(r'[,|]',str(value or '')); out=[]
    for item in raw:
        for part in re.split(r'[,|]',str(item or '')):
            part=part.strip()
            if part and part not in out: out.append(part)
    return out
def form_list(form,name):
    if hasattr(form,'getlist'): raw=form.getlist(name)
    elif hasattr(form,'get'): raw=[form.get(name)]
    else:
        try: raw=[form[name]]
        except (KeyError,IndexError,TypeError): raw=[]
    return csv_values(raw)
def reject_repeated_scalar_values(form):
    if hasattr(form,'getlist'):
        for name in form.keys():
            if name!='dh_groups' and len(form.getlist(name))!=1: raise ValueError('El parámetro '+str(name)+' no puede repetirse.')
    elif hasattr(form,'items'):
        for name,value in form.items():
            if name!='dh_groups' and isinstance(value,(list,tuple)) and len(value)!=1: raise ValueError('El parámetro '+str(name)+' no puede repetirse.')
def multi_opts(items,current):
    selected=set(csv_values(current)); return ''.join(f"<option value='{h(k)}' {'selected' if str(k) in selected else ''}>{h(label)}</option>" for k,label in items)
def vf(v=None,forced_type=None,error=''):
    submitted_dh=form_list(v,'dh_groups') if v is not None else []
    vt=forced_type or ((v['vpn_type'] if v else None) or 'ssl'); v=dict(v) if v else {}
    if submitted_dh: v['dh_groups']=','.join(submitted_dh)
    editing=bool(v.get('id')); err=f"<div class='card error'><b>{h(error)}</b></div>" if error else ''
    target_fields='' if editing else '<input type=hidden name=onboarding_mode value=manual>'
    common=f'''<input type=hidden name=_csrf value="{h(csrf_token())}"><input type=hidden name=vpn_type value="{vt}"><div class=form-grid><div><label>Planta</label><input name=plant value="{h(v.get('plant'))}" required></div><div><label>Identificador interno</label><input name=slug value="{h(v.get('slug'))}" placeholder="automático"></div><div><label>Gateway host/IP</label><input name=host value="{h(v.get('host'))}" required></div>{target_fields}'''
    if vt=='ssl':
        tc=dec(v.get('trusted_cert_enc','')) if v.get('trusted_cert_enc') else ''
        accept_checked='checked' if (not editing or int(v.get('accept_gateway_certificate') or 0)) else ''
        return err+f'''<form class="card vpn-form" method=post><h2>VPN SSL Fortinet</h2><p class=muted>Solo contiene parámetros de openfortivpn.</p>{common}<div><label>Puerto SSL</label><input type=number min=1 max=65535 name=port value="{h(v.get('port') or '443')}" required></div><div><label>Usuario</label><input name=username value="{h(v.get('username'))}" required></div><div><label>Contraseña {'(vacío = mantener)' if editing else ''}</label><input type=password name=password {'required' if not editing else ''}></div></div><label class="tag-option" style="min-height:44px"><input type=checkbox name=accept_gateway_certificate value=1 {accept_checked}>Validación de certificado: aceptar el certificado presentado por el gateway</label><details class="card"><summary>Certificado avanzado</summary><label>Trusted certificate SHA-256</label><input name=trusted_cert value="{h(tc)}" pattern="[A-Fa-f0-9]{{64}}" placeholder="vacío = detección controlada"></details><button class="btn primary">Guardar, publicar y conectar</button></form>'''
    if vt=='openvpn':
        auth_fields=''
        if int(v.get('openvpn_requires_auth') or 0): auth_fields+=f'''<div><label>Usuario OpenVPN</label><input name=username value="{h(v.get('username'))}" required></div><div><label>Contraseña OpenVPN {'(vacío = mantener)' if editing else ''}</label><input type=password name=password {'required' if not editing else ''}></div>'''
        if int(v.get('openvpn_requires_key_pass') or 0): auth_fields+=f'''<div><label>Passphrase de clave privada {'(vacío = mantener)' if editing else ''}</label><input type=password name=openvpn_key_pass {'required' if not editing else ''}></div>'''
        stage_token=str(v.get('openvpn_stage_token') or ''); staged=bool(stage_token)
        upload='' if editing or staged else '<div><label>Archivo .ovpn</label><input type=file name=openvpn_file accept=".ovpn,text/plain" required></div>'
        stage_hidden=f'<input type=hidden name=openvpn_stage_token value="{h(stage_token)}">' if staged else ''
        return err+f'''<form class="card vpn-form" method=post enctype="multipart/form-data"><h2>VPN OpenVPN</h2><p class=muted>Importe un perfil cliente .ovpn. El gateway, rutas y requisitos de credenciales se detectan sin mostrar claves ni secretos.</p><input type=hidden name=_csrf value="{h(csrf_token())}"><input type=hidden name=vpn_type value=openvpn>{stage_hidden}<div class=form-grid><div><label>Planta</label><input name=plant value="{h(v.get('plant'))}" required></div><div><label>Identificador interno</label><input name=slug value="{h(v.get('slug'))}" placeholder="automático"></div>{upload}{auth_fields}{target_fields}</div><button class="btn primary">Guardar como borrador y validar</button></form>'''
    if vt=='pptp':
        return err+f'''<form class="card vpn-form" method=post><h2>VPN PPTP</h2><p class=muted>La ruta por defecto se instalará solo dentro del contenedor aislado de esta planta.</p>{common}<div><label>Usuario</label><input name=username value="{h(v.get('username'))}" required></div><div><label>Contraseña {'(vacío = mantener)' if editing else ''}</label><input type=password name=password {'required' if not editing else ''}></div></div><button class="btn primary">Guardar, publicar y conectar</button></form>'''
    ike=v.get('ike_version') or 'ikev1'; engine=v.get('ipsec_engine') or ('strongswan' if ike=='ikev2' else 'libreswan'); enc=[('aes128','AES-128'),('aes192','AES-192'),('aes256','AES-256'),('3des','3DES · legado')]; auth=[('sha1','SHA-1 · legado'),('sha256','SHA-256'),('sha384','SHA-384'),('sha512','SHA-512')]; dh=[('5','DH 5 · MODP 1536'),('14','DH 14 · MODP 2048'),('15','DH 15 · MODP 3072'),('16','DH 16 · MODP 4096'),('17','DH 17 · MODP 6144'),('18','DH 18 · MODP 8192'),('19','DH 19 · ECP 256'),('20','DH 20 · ECP 384'),('21','DH 21 · ECP 521')]
    return err+f'''<form class="card vpn-form" method=post id=ipsec-form><h2>VPN IPsec Fortinet</h2><p class=muted>IKEv1 puede usar Libreswan o strongSwan. IKEv2 usa strongSwan.</p>{common}<div><label>Puerto IKE</label><select name=port><option value=500>UDP 500 · NAT-T usa 4500 automáticamente</option></select></div><div><label>Usuario XAuth/EAP</label><input name=username value="{h(v.get('username'))}" required></div><div><label>Contraseña XAuth/EAP {'(vacío = mantener)' if editing else ''}</label><input type=password name=password {'required' if not editing else ''}></div><div><label>PSK {'(vacío = mantener)' if editing else ''}</label><input type=password name=psk {'required' if not editing else ''}></div><div><label>Versión IKE</label><select name=ike_version id=ike_version>{opts([('ikev1','IKEv1'),('ikev2','IKEv2')],ike)}</select></div><div id=engine-wrap><label>Motor IPsec</label><select name=ipsec_engine id=ipsec_engine>{opts([('libreswan','Libreswan'),('strongswan','strongSwan')],engine)}</select></div><div><label>Autenticación</label><select name=auth_mode id=auth_mode>{opts([('psk-xauth','PSK + XAuth'),('eap-mschapv2-psk','EAP-MSCHAPv2 cliente + PSK gateway')],'eap-mschapv2-psk' if ike=='ikev2' else 'psk-xauth')}</select></div><div id=aggr-wrap><label>Intercambio IKEv1</label><select name=exchange_mode>{opts([('aggressive','Aggressive Mode'),('main','Main Mode')],'aggressive' if int(v.get('aggressive') or 0) else 'main')}</select></div><div><label>Mode Config</label><select name=modecfg>{opts([('pull','Pull · cliente solicita IP'),('push','Push · gateway entrega IP')],v.get('modecfg') or 'pull')}</select></div><div><label>NAT Traversal</label><select name=nat_traversal>{opts([('1','Activado / automático'),('0','Desactivado')],str(int(v.get('nat_traversal') if v.get('nat_traversal') is not None else 1)))}</select></div><div><label>DPD</label><select name=dpd>{opts([('1','Activado · reiniciar'),('0','Desactivado')],str(int(v.get('dpd') if v.get('dpd') is not None else 1)))}</select></div></div><h3>Fase 1 · IKE SA</h3><div class=form-grid><div><label>Cifrado</label><select name=phase1_enc>{opts(enc,v.get('phase1_enc') or 'aes256')}</select></div><div><label>Integridad / PRF</label><select name=phase1_auth>{opts(auth,v.get('phase1_auth') or 'sha512')}</select></div><div data-ikev2-only><label>Propuesta 2 · Cifrado</label><select name="phase1_enc2">{opts([('','Desactivada')]+enc,v.get('phase1_enc2') or '')}</select></div><div data-ikev2-only><label>Propuesta 2 · Integridad / PRF</label><select name="phase1_auth2">{opts(auth,v.get('phase1_auth2') or v.get('phase1_auth') or 'sha512')}</select></div><div data-ikev1-only><label>Grupo DH · IKEv1</label><select name=dh_group>{opts(dh,(csv_values(v.get('dh_groups')) or [str(v.get('dh_group') or '14')])[0])}</select></div><div data-ikev2-only><label>Grupos DH marcados en FortiClient</label><select name="dh_groups" multiple size="9" required>{multi_opts(dh,v.get('dh_groups') or v.get('dh_group') or '14')}</select><span class=muted>Use Ctrl/Cmd para seleccionar varios.</span></div><div><label>Vida Fase 1</label><select name=phase1_lifetime>{opts([('3600','1 hora'),('28800','8 horas'),('43200','12 horas'),('86400','24 horas')],str(v.get('phase1_lifetime') or '86400'))}</select></div></div><h3>Fase 2 · ESP/CHILD SA</h3><div class=form-grid><div><label>Cifrado ESP</label><select name=phase2_enc>{opts(enc,v.get('phase2_enc') or 'aes256')}</select></div><div><label>Integridad ESP</label><select name=phase2_auth>{opts(auth,v.get('phase2_auth') or 'sha512')}</select></div><div data-ikev2-only><label>Propuesta 2 · Cifrado ESP</label><select name="phase2_enc2">{opts([('','Desactivada')]+enc,v.get('phase2_enc2') or '')}</select></div><div data-ikev2-only><label>Propuesta 2 · Integridad ESP</label><select name="phase2_auth2">{opts(auth,v.get('phase2_auth2') or v.get('phase2_auth') or 'sha512')}</select></div><div><label>Vida Fase 2</label><select name=phase2_lifetime>{opts([('1800','30 minutos'),('3600','1 hora'),('7200','2 horas'),('28800','8 horas'),('43200','12 horas')],str(v.get('phase2_lifetime') or '43200'))}</select></div><div><label>PFS</label><select name=pfs>{opts([('0','Desactivado'),('1','Activado · mismo grupo DH')],str(int(v.get('pfs') or 0)))}</select></div><div data-ikev2-only><label>Grupo PFS</label><select name="pfs_group">{opts(dh,v.get('pfs_group') or v.get('dh_group') or '14')}</select></div><div><label>Selector remoto</label><select name=remote_subnet><option value="0.0.0.0/0">0.0.0.0/0 · FortiGate limita por Mode Config</option></select></div></div><h3>Identidades opcionales</h3><p class=muted>No son el nombre de la VPN ni el usuario EAP. Vacías si FortiClient no muestra un valor.</p><div class=form-grid><div><label>Local ID</label><input name=local_id maxlength=255 value="{h(v.get('local_id'))}"></div><div><label>Remote ID <span class=muted>(vacío = detectar y fijar automáticamente)</span></label><input name=remote_id maxlength=255 value="{h(v.get('remote_id'))}"></div></div><button class="btn primary">Guardar, publicar y conectar</button></form><script>(function(){{let i=document.getElementById('ike_version'),e=document.getElementById('ipsec_engine'),a=document.getElementById('auth_mode'),g=document.getElementById('aggr-wrap');function s(){{a.value=i.value==='ikev2'?'eap-mschapv2-psk':'psk-xauth';if(i.value==='ikev2')e.value='strongswan';g.style.display=i.value==='ikev2'?'none':'block';document.querySelectorAll('[data-ikev2-only]').forEach(function(w){{let on=i.value==='ikev2';w.style.display=on?'':'none';w.querySelectorAll('select,input').forEach(function(x){{x.disabled=!on}})}});document.querySelectorAll('[data-ikev1-only]').forEach(function(w){{let on=i.value==='ikev1';w.style.display=on?'':'none';w.querySelectorAll('select,input').forEach(function(x){{x.disabled=!on}})}})}}i.onchange=s;s()}})()</script>'''
ENUMS={'phase1_enc':{'aes128','aes192','aes256','3des'},'phase2_enc':{'aes128','aes192','aes256','3des'},'phase1_auth':{'sha1','sha256','sha384','sha512'},'phase2_auth':{'sha1','sha256','sha384','sha512'},'dh_group':{'5','14','15','16','17','18','19','20','21'},'phase1_lifetime':{'3600','28800','43200','86400'},'phase2_lifetime':{'1800','3600','7200','28800','43200'},'modecfg':{'pull','push'},'nat_traversal':{'0','1'},'dpd':{'0','1'},'pfs':{'0','1'},'remote_subnet':{'0.0.0.0/0'}}
def openvpn_values(form, parsed, profile_bytes, old=None):
    old=dict(old) if old else {}
    if not isinstance(profile_bytes,(bytes,bytearray)) or parsed.get('profile') != bytes(profile_bytes).decode('utf-8-sig'):
        raise ValueError('El perfil OpenVPN no coincide con el análisis validado.')
    plant=(form.get('plant') or '').strip(); sl=slug((form.get('slug') or plant).strip())
    if not plant or not sl: raise ValueError('Planta e identificador son obligatorios.')
    requires_auth=bool(parsed.get('requires_auth')); requires_key_pass=bool(parsed.get('requires_key_pass'))
    username=(form.get('username') or '').strip() if requires_auth else ''
    password=form.get('password') or ''
    key_pass=form.get('openvpn_key_pass') or ''
    if requires_auth:
        if not username: raise ValueError('El perfil OpenVPN requiere usuario.')
        if password: validate_config_secret(password,'La contraseña OpenVPN')
        if not password and not old.get('password_enc'): raise ValueError('El perfil OpenVPN requiere contraseña.')
    else: password=''
    if requires_key_pass:
        if key_pass: validate_config_secret(key_pass,'La passphrase OpenVPN')
        if not key_pass and not old.get('openvpn_key_pass_enc'): raise ValueError('La clave privada OpenVPN requiere passphrase.')
    else: key_pass=''
    return dict(plant=plant,slug=sl,host=parsed['host'],port=parsed['port'],username=username,password_enc=enc(password) if password else old.get('password_enc',''),trusted_cert_enc='',vpn_type='openvpn',ipsec_engine='libreswan',psk_enc='',ike_version='ikev1',auth_mode='',aggressive=0,phase1_enc='aes256',phase1_auth='sha256',dh_group='14',phase1_enc2='',phase1_auth2='',dh_groups='14',phase1_lifetime='86400',dpd=1,nat_traversal=1,phase2_enc='aes256',phase2_auth='sha256',phase2_enc2='',phase2_auth2='',phase2_lifetime='43200',pfs=0,pfs_group='',local_id='',remote_id='',modecfg='pull',remote_subnet='0.0.0.0/0',openvpn_profile_enc=enc(parsed['profile']),openvpn_key_pass_enc=enc(key_pass) if key_pass else old.get('openvpn_key_pass_enc',''),openvpn_requires_auth=int(requires_auth),openvpn_requires_key_pass=int(requires_key_pass),openvpn_routes=','.join(parsed['routes']))

def vpn_vals(f,old=None,forced_type=None):
    reject_repeated_scalar_values(f)
    old=dict(old) if old else {}; vt=forced_type or f.get('vpn_type'); plant=(f.get('plant') or '').strip(); host=(f.get('host') or '').strip(); sl=slug((f.get('slug') or plant).strip())
    if vt not in VPN_TYPES or not plant or not host or not sl: raise ValueError('Tipo, planta, gateway e identificador son obligatorios.')
    if not re.fullmatch(r'[A-Za-z0-9.-]+',host): raise ValueError('Gateway no válido: use IP o nombre DNS.')
    username=(f.get('username') or '').strip(); pwd=f.get('password') or ''
    if pwd: validate_config_secret(pwd,'La contraseña')
    if not username or (not pwd and not old.get('password_enc')): raise ValueError('Usuario y contraseña son obligatorios.')
    base=dict(plant=plant,slug=sl,host=host,username=username,password_enc=enc(pwd) if pwd else old.get('password_enc',''),vpn_type=vt,accept_gateway_certificate=1 if vt=='ssl' and f.get('accept_gateway_certificate')=='1' else 0)
    if vt=='pptp':
        return dict(base,port='1723',trusted_cert_enc='',ipsec_engine='libreswan',psk_enc='',ike_version='ikev1',auth_mode='',aggressive=0,phase1_enc='aes256',phase1_auth='sha256',dh_group='14',phase1_enc2='',phase1_auth2='',dh_groups='14',phase1_lifetime='86400',dpd=1,nat_traversal=1,phase2_enc='aes256',phase2_auth='sha256',phase2_enc2='',phase2_auth2='',phase2_lifetime='43200',pfs=0,pfs_group='',local_id='',remote_id='',modecfg='pull',remote_subnet='0.0.0.0/0')
    if vt=='ssl':
        port=(f.get('port') or '443').strip(); tc=(f.get('trusted_cert') or '').strip().lower()
        if not port.isdigit() or not 1<=int(port)<=65535: raise ValueError('Puerto SSL fuera de rango.')
        if tc and not re.fullmatch(r'[a-f0-9]{64}',tc): raise ValueError('trusted-cert debe ser SHA-256 hexadecimal de 64 caracteres.')
        return dict(base,port=port,trusted_cert_enc=enc(tc),ipsec_engine=old.get('ipsec_engine','libreswan'),psk_enc=old.get('psk_enc',''),ike_version=old.get('ike_version','ikev1'),auth_mode=old.get('auth_mode',''),aggressive=0,phase1_enc=old.get('phase1_enc','aes256'),phase1_auth=old.get('phase1_auth','sha256'),dh_group=old.get('dh_group','14'),phase1_enc2=old.get('phase1_enc2',''),phase1_auth2=old.get('phase1_auth2',''),dh_groups=old.get('dh_groups') or old.get('dh_group','14'),phase1_lifetime=old.get('phase1_lifetime','86400'),dpd=1,nat_traversal=1,phase2_enc=old.get('phase2_enc','aes256'),phase2_auth=old.get('phase2_auth','sha256'),phase2_enc2=old.get('phase2_enc2',''),phase2_auth2=old.get('phase2_auth2',''),phase2_lifetime=old.get('phase2_lifetime','43200'),pfs=0,pfs_group=old.get('pfs_group',''),local_id='',remote_id='',modecfg='pull',remote_subnet='0.0.0.0/0')
    for n,allowed in ENUMS.items():
        if n=='dh_group': continue
        if (f.get(n) or '') not in allowed: raise ValueError('Valor IPsec no válido para '+n+'.')
    enc_allowed=ENUMS['phase1_enc']; auth_allowed=ENUMS['phase1_auth']; dh_allowed=ENUMS['dh_group']
    p1e2=(f.get('phase1_enc2') or '').strip(); p1a2=(f.get('phase1_auth2') or '').strip() if p1e2 else ''
    p2e2=(f.get('phase2_enc2') or '').strip(); p2a2=(f.get('phase2_auth2') or '').strip() if p2e2 else ''
    if p1e2 and (p1e2 not in enc_allowed or p1a2 not in auth_allowed): raise ValueError('Propuesta 2 de Fase 1 no válida.')
    if p2e2 and (p2e2 not in enc_allowed or p2a2 not in auth_allowed): raise ValueError('Propuesta 2 de Fase 2 no válida.')
    dh_values=form_list(f,'dh_groups') or [(f.get('dh_group') or '').strip()]
    if not dh_values or any(x not in dh_allowed for x in dh_values): raise ValueError('Seleccione al menos un grupo DH válido.')
    pfs_enabled=int(f['pfs']); pfs_group=(f.get('pfs_group') or dh_values[0]).strip()
    if pfs_enabled and pfs_group not in dh_allowed: raise ValueError('Grupo PFS no válido.')
    ike=f.get('ike_version'); auth_mode=f.get('auth_mode'); expected='psk-xauth' if ike=='ikev1' else 'eap-mschapv2-psk'; engine=(f.get('ipsec_engine') or old.get('ipsec_engine') or ('strongswan' if ike=='ikev2' else 'libreswan'))
    if ike not in {'ikev1','ikev2'} or auth_mode!=expected: raise ValueError('Autenticación incompatible con la versión IKE.')
    ikev1_extra=ike=='ikev1' and (f.get('dh_groups') is not None or f.get('pfs_group') is not None or any(form_list(f,name) for name in ('phase1_enc2','phase1_auth2','phase2_enc2','phase2_auth2')))
    if ikev1_extra: raise ValueError('Las propuestas múltiples y el grupo PFS independiente solo están disponibles para IKEv2.')
    if ike=='ikev2' and f.get('dh_group') is not None: raise ValueError('El grupo DH simple solo está disponible para IKEv1; use la selección múltiple IKEv2.')
    if engine not in {'libreswan','strongswan'} or (ike=='ikev2' and engine!='strongswan'): raise ValueError('Motor IPsec incompatible con la versión IKE.')
    psk=f.get('psk') or ''
    if psk: validate_config_secret(psk,'La PSK')
    if not psk and not old.get('psk_enc'): raise ValueError('La PSK es obligatoria.')
    lid=(f.get('local_id') or '').strip(); rid=(f.get('remote_id') or '').strip()
    if any(x in lid+rid+username for x in '\r\n\t"'): raise ValueError('Identidad IKE o usuario no válido.')
    return dict(base,port='500',trusted_cert_enc=old.get('trusted_cert_enc',enc('')),ipsec_engine=engine,psk_enc=enc(psk) if psk else old.get('psk_enc',''),ike_version=ike,auth_mode=auth_mode,aggressive=1 if ike=='ikev1' and f.get('exchange_mode')=='aggressive' else 0,phase1_enc=f['phase1_enc'],phase1_auth=f['phase1_auth'],dh_group=dh_values[0],phase1_enc2=p1e2,phase1_auth2=p1a2,dh_groups=','.join(dh_values),phase1_lifetime=f['phase1_lifetime'],dpd=int(f['dpd']),nat_traversal=int(f['nat_traversal']),phase2_enc=f['phase2_enc'],phase2_auth=f['phase2_auth'],phase2_enc2=p2e2,phase2_auth2=p2a2,phase2_lifetime=f['phase2_lifetime'],pfs=pfs_enabled,pfs_group=pfs_group if pfs_enabled else '',local_id=lid,remote_id=rid,modecfg=f['modecfg'],remote_subnet=f['remote_subnet'])
WRITE=['plant','slug','host','port','username','password_enc','trusted_cert_enc','accept_gateway_certificate','vpn_type','ipsec_engine','psk_enc','ike_version','auth_mode','aggressive','phase1_enc','phase1_auth','dh_group','phase1_enc2','phase1_auth2','dh_groups','phase1_lifetime','dpd','nat_traversal','phase2_enc','phase2_auth','phase2_enc2','phase2_auth2','phase2_lifetime','pfs','pfs_group','local_id','remote_id','modecfg','remote_subnet','openvpn_profile_enc','openvpn_key_pass_enc','openvpn_requires_auth','openvpn_requires_key_pass','openvpn_routes']
def plant_variants(value):
    key=plant_key(value); values=[]
    for table in ('vpns','equipment'):
        for row in db().execute(f"SELECT DISTINCT plant FROM {table} WHERE plant IS NOT NULL"):
            if plant_key(row[0])==key and row[0] not in values: values.append(row[0])
    return values
def canonical_plant_name(value):
    key=plant_key(value)
    for table in ('vpns','equipment'):
        for row in db().execute(f"SELECT plant FROM {table} WHERE plant IS NOT NULL ORDER BY id"):
            if plant_key(row[0])==key: return normalize_plant_name(row[0])
    return None
def save_vpn(vals,i=None,draft=False,onboarding=None,transaction_conn=None,commit=True):
    conn=transaction_conn or db(); vals=dict(vals)
    if i:
        existing=conn.execute('SELECT slug FROM vpns WHERE id=?',(i,)).fetchone()
        if not existing:raise ValueError('La VPN ya no existe.')
        vals['slug']=existing['slug']
    for key,default in {'openvpn_profile_enc':'','openvpn_key_pass_enc':'','openvpn_requires_auth':0,'openvpn_requires_key_pass':0,'openvpn_routes':''}.items(): vals.setdefault(key,default)
    vals['plant']=normalize_plant_name(vals.get('plant'))
    if not vals['plant']: raise ValueError('La planta es obligatoria.')
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',str(vals.get('slug') or '')): raise ValueError('Identificador VPN no válido.')
    meta=dict(onboarding or {});target_ip=str(meta.get('validation_target_ip') or '')
    declared=remote_subnets(vals) if target_ip else []
    if declared and not any(ipaddress.ip_address(target_ip) in ipaddress.ip_network(net,strict=False) for net in declared): raise ValueError('El destino de validación no pertenece a las redes remotas declaradas.')
    if target_ip:
        addr=ipaddress.ip_address(target_ip)
        if addr.version!=4 or addr.is_unspecified or addr.is_multicast or addr.is_reserved or addr.is_loopback or addr.is_link_local or any(addr in net for net in validation_deny_networks()):raise ValueError('El destino de validación pertenece a una red no permitida.')
        if not declared:meta['remote_subnets_json']=json.dumps([target_ip+'/32']);onboarding=meta
    for row in conn.execute('SELECT id,plant FROM vpns'):
        if row['id']!=i and plant_key(row['plant'])==plant_key(vals['plant']): raise ValueError('Ya existe una VPN para esa planta.')
    try:
        if i:
            old=conn.execute('SELECT plant FROM vpns WHERE id=?',(i,)).fetchone()
            if not old: raise ValueError('La VPN ya no existe.')
            oldplant=old['plant'];conn.execute('UPDATE vpns SET '+','.join(x+'=?' for x in WRITE)+' WHERE id=?',[vals[x] for x in WRITE]+[i]);conn.execute("update vpns set onboarding_revision=coalesce(onboarding_revision,0)+1,reconcile_lock_token='',reconcile_lock_until=null where id=?",(i,))
            if oldplant!=vals['plant']:
                conn.execute('UPDATE equipment SET plant=? WHERE plant=?',(vals['plant'],oldplant));conn.execute('INSERT OR IGNORE INTO plant_permissions(user_id,plant) SELECT user_id,? FROM plant_permissions WHERE plant=?',(vals['plant'],oldplant));conn.execute('DELETE FROM plant_permissions WHERE plant=?',(oldplant,))
        else:
            cols=WRITE+['active','created_at'];data=[vals[x] for x in WRITE]+[0 if draft else 1,datetime.now().isoformat(timespec='seconds')]
            if draft:
                meta=dict(onboarding or {});extra=['onboarding_state','validation_stage','validation_code','validation_detail','validation_target_ip','validation_target_port','next_retry_at','last_checked_at','retry_count','auto_activate','profile_source','phase1_proposals_json','phase2_proposals_json','remote_subnets_json','dpd_retry_count','dpd_retry_interval'];defaults={'onboarding_state':'draft','validation_stage':'local','validation_code':'pending','validation_detail':'Pendiente de validación local.','next_retry_at':None,'last_checked_at':None,'retry_count':0,'auto_activate':1,'profile_source':'manual','phase1_proposals_json':'','phase2_proposals_json':'','remote_subnets_json':'','dpd_retry_count':3,'dpd_retry_interval':5};cols+=extra;data += [meta.get(x,vals.get(x,defaults.get(x,''))) for x in extra]
            conn.execute('INSERT INTO vpns('+','.join(cols)+') VALUES('+','.join('?' for _ in cols)+')',data)
        if commit:conn.commit()
    except Exception:
        conn.rollback();raise
    return conn.execute('SELECT * FROM vpns WHERE id=?',(i,)).fetchone() if i else conn.execute('SELECT * FROM vpns WHERE slug=?',(vals['slug'],)).fetchone()

def onboarding_target(form):
    reject_repeated_scalar_values(form)
    return '',None,1 if form.get('auto_activate','1')=='1' else 0

def forticlient_upload_form(kind,error=''):
    label='IPsec' if kind=='ipsec' else 'SSL';err=f"<div class='card error'><b>{h(error)}</b></div>" if error else ''
    return err+f'''<form class="card vpn-form" method="post" enctype="multipart/form-data"><h2>Importar VPN {label} desde FortiClient</h2><p class="muted">El archivo se analiza en memoria; no se guardan el XML ni sus bloques cifrados.</p><input type="hidden" name="_csrf" value="{h(csrf_token())}"><input type="hidden" name="onboarding_action" value="upload"><label>Backup FortiClient XML</label><input type="file" name="forticlient_file" accept=".conf,.xml,text/xml,application/xml" required><button class="btn primary">Analizar perfiles</button></form><a class="btn outline" href="/admin/vpns/new/{kind}?mode=manual">Configuración manual avanzada</a>'''

def forticlient_select_form(kind,token,profiles):
    rows=[]
    for i,p in enumerate(profiles):
        required='required' if i==0 else '';rows.append(f'''<label class="card"><input type="radio" name="profile_index" value="{i}" {required}><b>{h(p['profile_name'])}</b><div class="muted">{h(p['kind'].upper())} · {h(p.get('ike_version','SSL'))} · {h(p['host'])}:{h(p['port'])}</div></label>''')
    return f'''<form method="post"><h2>Perfiles VPN encontrados</h2><p class="muted">Seleccione e importe una VPN cada vez.</p><input type="hidden" name="_csrf" value="{h(csrf_token())}"><input type="hidden" name="onboarding_action" value="select"><input type="hidden" name="forticlient_stage_token" value="{h(token)}">{''.join(rows)}<button class="btn primary">Revisar perfil seleccionado</button></form>'''

def imported_review_form(kind,token,index,profile,error=''):
    err=f"<div class='card error'><b>{h(error)}</b></div>" if error else '';plant=profile['profile_name']
    if kind=='ipsec':
        p1=', '.join(x['encryption'].upper()+' / '+x['integrity'].upper() for x in profile['phase1_proposals']);p2=', '.join(x['encryption'].upper()+' / '+x['integrity'].upper() for x in profile['phase2_proposals'])
        summary=f'''<div class="card"><b>Perfil FortiClient</b><p>{h(profile['ike_version'].upper())} · {h(profile['exchange_mode'])} · DH {h(', '.join(profile['dh_groups']))}</p><p class="muted">Phase 1: {h(p1)}<br>Phase 2: {h(p2)} · PFS {h(profile['pfs_group'] if profile['pfs_enabled'] else 'desactivado')}<br>Origen: perfil</p></div>'''
        secret_fields='''<div><label>Usuario XAuth/EAP</label><input name="username" autocomplete="off" required></div><div><label>Contraseña XAuth/EAP</label><input type="password" name="password" autocomplete="new-password" required></div><div><label>PSK</label><input type="password" name="psk" autocomplete="new-password" required></div>'''
        advanced='''<details class="card"><summary>Opciones avanzadas</summary><label>Motor IPsec</label><select name="ipsec_engine"><option value="strongswan" selected>strongSwan (recomendado)</option><option value="libreswan">Libreswan</option></select><p class="muted">Las propuestas, DH, PFS, lifetimes e IDs proceden del perfil y no se alteran silenciosamente.</p></details>'''
    else:
        summary=f'''<div class="card"><b>Perfil FortiClient</b><p>SSL · {h(profile['host'])}:{h(profile['port'])}</p><p class="muted">La huella del certificado se confirmará antes de activar.</p></div>''';secret_fields='''<div><label>Usuario SSL</label><input name="username" autocomplete="off" required></div><div><label>Contraseña SSL</label><input type="password" name="password" autocomplete="new-password" required></div>''';advanced='''<label class="tag-option" style="min-height:44px"><input type="checkbox" name="accept_gateway_certificate" value="1" checked>Validación de certificado: aceptar el certificado presentado por el gateway</label>'''
    return err+summary+f'''<form class="card vpn-form" method="post"><input type="hidden" name="_csrf" value="{h(csrf_token())}"><input type="hidden" name="onboarding_action" value="create"><input type="hidden" name="forticlient_stage_token" value="{h(token)}"><input type="hidden" name="profile_index" value="{index}"><div class="form-grid"><div><label>Planta</label><input name="plant" value="{h(plant)}" required></div><div><label>Identificador interno</label><input name="slug" value="{h(slug(plant))}" required></div>{secret_fields}</div><input type="hidden" name="auto_activate" value="1">{advanced}<button class="btn primary">Crear borrador y validar</button></form>'''

def imported_profile_values(profile,form):
    plant=(form.get('plant') or '').strip();sl=slug((form.get('slug') or plant).strip());username=(form.get('username') or '').strip();credential=form.get('password') or ''
    if not plant or not sl or not username or not credential: raise ValueError('Planta, identificador y credenciales son obligatorios.')
    validate_config_secret(credential,'La credencial VPN');kind=profile['kind']
    base=dict(plant=plant,slug=sl,host=profile['host'],port=profile['port'],username=username,password_enc=enc(credential),trusted_cert_enc='',accept_gateway_certificate=1 if kind=='ssl' and form.get('accept_gateway_certificate')=='1' else 0,vpn_type=kind,ipsec_engine='',psk_enc='',ike_version='ikev1',auth_mode='',aggressive=0,phase1_enc='aes256',phase1_auth='sha256',dh_group='14',phase1_enc2='',phase1_auth2='',dh_groups='14',phase1_lifetime='86400',dpd=1,nat_traversal=1,phase2_enc='aes256',phase2_auth='sha256',phase2_enc2='',phase2_auth2='',phase2_lifetime='43200',pfs=0,pfs_group='',local_id='',remote_id='',modecfg='pull',remote_subnet='0.0.0.0/0',openvpn_profile_enc='',openvpn_key_pass_enc='',openvpn_requires_auth=0,openvpn_requires_key_pass=0,openvpn_routes='')
    if kind=='ssl': return base
    psk=form.get('psk') or ''
    if not psk: raise ValueError('La PSK es obligatoria.')
    validate_config_secret(psk,'La PSK');engine=form.get('ipsec_engine') or profile.get('engine') or 'strongswan'
    if engine not in {'strongswan','libreswan'} or (profile['ike_version']=='ikev2' and engine!='strongswan'):raise ValueError('Motor IPsec incompatible con el perfil.')
    p1=profile['phase1_proposals'];p2=profile['phase2_proposals'];base.update(ipsec_engine=engine,psk_enc=enc(psk),ike_version=profile['ike_version'],auth_mode=profile['auth_method'],aggressive=int(profile['exchange_mode']=='aggressive'),phase1_enc=p1[0]['encryption'],phase1_auth=p1[0]['integrity'],phase1_enc2=(p1[1]['encryption'] if len(p1)>1 else ''),phase1_auth2=(p1[1]['integrity'] if len(p1)>1 else ''),dh_group=profile['dh_groups'][0],dh_groups=','.join(profile['dh_groups']),phase1_lifetime=str(profile['phase1_lifetime']),dpd=int(profile['dpd_enabled']),nat_traversal=int(profile['nat_traversal']),phase2_enc=p2[0]['encryption'],phase2_auth=p2[0]['integrity'],phase2_enc2=(p2[1]['encryption'] if len(p2)>1 else ''),phase2_auth2=(p2[1]['integrity'] if len(p2)>1 else ''),phase2_lifetime=str(profile['phase2_lifetime']),pfs=int(profile['pfs_enabled']),pfs_group=profile['pfs_group'],local_id=profile['local_id'],remote_id=profile['remote_id'],modecfg='pull',remote_subnet=(profile['remote_subnets'][0] if len(profile['remote_subnets'])==1 else '0.0.0.0/0'))
    return base

def imported_onboarding(profile,target):
    ip,port,auto=target
    return {'validation_target_ip':ip,'validation_target_port':port,'auto_activate':auto,'profile_source':json.dumps(profile['source'],separators=(',',':'),sort_keys=True),'phase1_proposals_json':json.dumps(profile.get('phase1_proposals',[]),separators=(',',':')),'phase2_proposals_json':json.dumps(profile.get('phase2_proposals',[]),separators=(',',':')),'remote_subnets_json':json.dumps(profile.get('remote_subnets',[]),separators=(',',':')),'dpd_retry_count':profile.get('dpd_retry_count',3),'dpd_retry_interval':profile.get('dpd_retry_interval',5)}

@app.route('/admin/vpns/new')
@admin
def vpn_new(): return page('Seleccionar tipo de VPN',"<div class=grid><a class=card href=/admin/vpns/new/ssl><h2>VPN SSL Fortinet</h2><p>Importar perfil o manual</p></a><a class=card href=/admin/vpns/new/ipsec><h2>VPN IPsec Fortinet</h2><p>Importar perfil o manual avanzado</p></a><a class=card href=/admin/vpns/new/pptp><h2>VPN PPTP</h2><p>PPP aislado por planta</p></a><a class=card href=/admin/vpns/new/openvpn><h2>VPN OpenVPN</h2><p>Importar archivo .ovpn</p></a></div>")
@app.route('/admin/vpns/new/<kind>',methods=['GET','POST'])
@admin
def vpn_new_kind(kind):
    if kind not in VPN_TYPES: abort(404)
    actor=str(me()['id'])
    if request.method=='GET':
        if kind in {'ssl','ipsec'} and request.args.get('mode')!='manual':return page('Nueva VPN '+kind.upper(),forticlient_upload_form(kind))
        return page('Nueva VPN '+kind.upper(),vf(None,kind))
    try: verify_onboarding_csrf(request.form)
    except ValueError as e: return page('Nueva VPN '+kind.upper(),forticlient_upload_form(kind,str(e)) if kind in {'ssl','ipsec'} else vf(request.form,kind,str(e))),400
    if kind in {'ssl','ipsec'} and request.form.get('onboarding_mode')!='manual':
        action=request.form.get('onboarding_action') or ''
        try:
            if action=='upload':
                upload=request.files.get('forticlient_file')
                if not upload or not upload.filename:raise ValueError('Seleccione un backup FortiClient XML.')
                profiles=[p for p in parse_forticlient_backup(upload.stream.read(MAX_FORTICLIENT_BYTES+1)) if p['kind']==kind]
                if not profiles:raise ValueError('El archivo no contiene perfiles '+kind.upper()+' compatibles.')
                token=stage_profiles(db(),actor,profiles,enc);return page('Seleccionar perfil VPN',forticlient_select_form(kind,token,profiles))
            token=request.form.get('forticlient_stage_token') or '';profiles=load_stage(db(),actor,token,dec)
            if not profiles:raise ValueError('La importación FortiClient ha caducado. Vuelva a subir el archivo.')
            index=request.form.get('profile_index') or ''
            if not index.isdigit() or not 0<=int(index)<len(profiles):raise ValueError('Seleccione un perfil VPN válido.')
            profile=profiles[int(index)]
            if profile.get('kind')!=kind:raise ValueError('El tipo del perfil no coincide con el asistente.')
            if action=='select':return page('Revisar perfil VPN',imported_review_form(kind,token,int(index),profile))
            if action!='create':raise ValueError('Paso de importación no válido.')
            target=onboarding_target(request.form);conn=db()
            try:
                save_vpn(imported_profile_values(profile,request.form),draft=True,onboarding=imported_onboarding(profile,target),transaction_conn=conn,commit=False)
                if not consume_stage(conn,actor,token,commit=False):raise sqlite3.IntegrityError('El staging ya fue consumido.')
                conn.commit()
            except Exception:
                conn.rollback();raise
            flash('Borrador creado. La VPN se validará de forma aislada antes de activarse.');return redirect('/admin/vpns')
        except (ValueError,FortiClientProfileError,sqlite3.IntegrityError) as e:
            if action=='create' and 'profiles' in locals() and profiles and 'index' in locals() and str(index).isdigit() and int(index)<len(profiles):body=imported_review_form(kind,request.form.get('forticlient_stage_token',''),int(index),profiles[int(index)],str(e))
            else:body=forticlient_upload_form(kind,str(e))
            return page('Nueva VPN '+kind.upper(),body),400
    try:
        target=onboarding_target(request.form)
        if kind=='openvpn':
            stage_token=request.form.get('openvpn_stage_token') or ''
            if stage_token:
                staged=load_openvpn_import(db(),actor,stage_token)
                if not staged:raise ValueError('La importación OpenVPN ha caducado. Vuelva a subir el perfil.')
                raw=staged['profile'].encode();parsed=parse_openvpn_profile(raw);vals=openvpn_values(request.form,parsed,raw)
            else:
                upload=request.files.get('openvpn_file')
                if not upload or not upload.filename:raise ValueError('Seleccione un archivo .ovpn.')
                raw=upload.stream.read(OPENVPN_MAX_BYTES+1);parsed=parse_openvpn_profile(raw)
                if parsed['requires_auth'] or parsed['requires_key_pass']:
                    token=stage_openvpn_import(db(),actor,request.form,parsed,raw);form_values=dict(request.form);form_values.update({'vpn_type':'openvpn','openvpn_stage_token':token,'openvpn_requires_auth':int(parsed['requires_auth']),'openvpn_requires_key_pass':int(parsed['requires_key_pass'])});return page('Nueva VPN OPENVPN',vf(form_values,'openvpn'))
                vals=openvpn_values(request.form,parsed,raw)
        else:vals=vpn_vals(request.form,forced_type=kind)
        conn=db()
        if kind=='openvpn' and stage_token:
            try:
                save_vpn(vals,draft=True,onboarding={'validation_target_ip':target[0],'validation_target_port':target[1],'auto_activate':target[2],'profile_source':'manual'},transaction_conn=conn,commit=False)
                if not consume_openvpn_import(conn,actor,stage_token,commit=False):raise sqlite3.IntegrityError('El staging ya fue consumido.')
                conn.commit()
            except Exception:
                conn.rollback();raise
        else:save_vpn(vals,draft=True,onboarding={'validation_target_ip':target[0],'validation_target_port':target[1],'auto_activate':target[2],'profile_source':'manual'})
        flash('Borrador creado. La VPN se validará de forma aislada antes de activarse.');return redirect('/admin/vpns')
    except (ValueError,sqlite3.IntegrityError) as e:return page('Nueva VPN '+kind.upper(),vf(request.form,kind,str(e))),400
def reset_inactive_vpn_draft(v):
    sl=v['slug']
    try:subprocess.run(['docker','rm','-f','vpn-'+sl],text=True,capture_output=True,timeout=60)
    except (FileNotFoundError,subprocess.TimeoutExpired):pass
    for path in (f'{BASE}/configs/{sl}',f'{BASE}/sites/{sl}'):
        if os.path.isdir(path):shutil.rmtree(path)
    db().execute("UPDATE vpns SET active=0,onboarding_state='draft',validation_stage='local',validation_code='pending',validation_detail='Pendiente de validación local.',next_retry_at=NULL,retry_count=0 WHERE id=?",(v['id'],));db().commit()

@app.route('/admin/vpns/<int:i>/edit',methods=['GET','POST'])
@admin
@vpn_mutation_lock
def vpn_edit(i):
    v=db().execute('SELECT * FROM vpns WHERE id=?',(i,)).fetchone()
    if not v:abort(404)
    kind=v['vpn_type'] or 'ssl'
    if request.method=='POST':
        try:verify_onboarding_csrf(request.form)
        except ValueError as e:return page('Editar VPN '+kind.upper(),vf(v,kind,str(e))),400
        if int(v['active'] or 0):
            return page('Editar VPN '+kind.upper(),vf(v,kind,'Las VPN activas no se editan in-place. Cree una revisión controlada para no sustituir un runtime operativo sin rollback durable.')),409
        try:
            if kind=='openvpn':
                raw=dec(v['openvpn_profile_enc']).encode()
                if not raw:raise ValueError('Falta el perfil OpenVPN cifrado.')
                vals=openvpn_values(request.form,parse_openvpn_profile(raw),raw,v)
            else:vals=vpn_vals(request.form,v,kind)
            prepare_draft_edit(i)
            v2=save_vpn(vals,i)
            reset_inactive_vpn_draft(v2)
        except (ValueError,sqlite3.IntegrityError) as e:return page('Editar VPN '+kind.upper(),vf(v,kind,str(e))),400
        flash('Borrador actualizado; volverá a validarse de forma aislada.');return redirect('/admin/vpns')
    health=endpoint_health_map([v]).get(int(v['id']))
    return page('Editar VPN '+kind.upper(),vf(v,kind)+endpoint_health_admin_markup(health)+endpoint_history_admin_markup(i))

def ensure_haproxy(sl, plant):
    hp=f'{BASE}/configs/{sl}/haproxy.cfg'
    if not os.path.exists(hp):
        text="global\n    log stdout format raw local0\n\ndefaults\n    log global\n    mode http\n    timeout connect 10s\n    timeout client 120s\n    timeout server 120s\n\nfrontend onboarding-health\n    bind 127.0.0.1:8404\n    mode http\n    http-request return status 200 content-type text/plain string ok\n\n# Añadir aquí frontends/backends de equipos de %s.\n" % plant
        with open(hp,'w') as out:out.write(text)
def gen_access_compose(v, sl):
    vpn_type=v['vpn_type']
    if vpn_type not in {'pptp','openvpn'}: raise ValueError('Tipo de VPN de acceso no válido.')
    mounts=[f'      - ./configs/{sl}/haproxy.cfg:/etc/haproxy/haproxy.cfg:ro']
    if vpn_type=='pptp':
        mounts += [f'      - ./configs/{sl}/start-pptp.sh:/etc/pptp/start-pptp.sh:ro',f'      - ./configs/{sl}/ppp-options:/etc/ppp/options.pptp:ro',f'      - ./configs/{sl}/chap-secrets:/etc/ppp/chap-secrets:ro']
    else:
        mounts += [f'      - ./configs/{sl}/client.ovpn:/etc/openvpn/client.ovpn:ro']
        if int(v['openvpn_requires_auth'] or 0): mounts += [f'      - ./configs/{sl}/auth.txt:/etc/openvpn/auth.txt:ro']
        if int(v['openvpn_requires_key_pass'] or 0): mounts += [f'      - ./configs/{sl}/askpass.txt:/etc/openvpn/askpass.txt:ro']
    device_block='      - /dev/net/tun:/dev/net/tun\n' if vpn_type=='openvpn' else ''
    compose=f'''services:
  vpn-{sl}:
    image: {runtime_image(vpn_type)}
    container_name: vpn-{sl}
    labels:
      plantas.vpn.slug: "{sl}"
      plantas.vpn.onboarding: "true"
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/ppp:/dev/ppp
{device_block}    environment:
      - VPN_CLIENT_TYPE={vpn_type}
      - BASTION_ACCESS_CIDRS=${{BASTION_ACCESS_CIDRS:?Set BASTION_ACCESS_CIDRS outside Git}}
    volumes:
{chr(10).join(mounts)}
    networks:
      - bastion
networks:
  bastion:
    external: true
    name: vpn_bastion_net
'''
    os.makedirs(f'{BASE}/sites/{sl}',exist_ok=True)
    with open(f'{BASE}/sites/{sl}/compose.yml','w') as fh: fh.write(compose)

def openvpn_profile_with_local_secrets(profile, requires_auth, requires_key_pass):
    lines=[]; inline=None; legacy_cbc=False; has_data_ciphers=False
    for raw_line in profile.splitlines():
        line=raw_line.strip(); tag=re.fullmatch(r'<(/?)([A-Za-z0-9-]+)>',line)
        if tag:
            closing,name=tag.groups(); inline=None if closing else name.lower(); lines.append(raw_line); continue
        directive=line.split()[0].lower() if line and not line.startswith(('#',';')) else ''
        if not inline and directive=='cipher' and len(line.split())>1 and line.split(None,1)[1].strip().upper()=='AES-256-CBC': legacy_cbc=True
        if not inline and directive=='data-ciphers': has_data_ciphers=True
        if not inline and directive=='auth-user-pass': continue
        lines.append(raw_line)
    if legacy_cbc and not has_data_ciphers:
        lines.append('data-ciphers AES-256-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305')
        lines.append('data-ciphers-fallback AES-256-CBC')
    if requires_auth: lines.append('auth-user-pass /etc/openvpn/auth.txt')
    if requires_key_pass: lines.append('askpass /etc/openvpn/askpass.txt')
    return '\n'.join(lines)+'\n'

def gen_openvpn(v, sl):
    profile=dec(v['openvpn_profile_enc'])
    if not profile: raise ValueError('Falta el perfil OpenVPN cifrado.')
    parsed=parse_openvpn_profile(profile.encode())
    requires_auth=bool(v['openvpn_requires_auth']); requires_key_pass=bool(v['openvpn_requires_key_pass'])
    if parsed['requires_auth']!=requires_auth or parsed['requires_key_pass']!=requires_key_pass: raise ValueError('Los requisitos OpenVPN no coinciden con el perfil validado.')
    cfgdir=f'{BASE}/configs/{sl}'; os.makedirs(cfgdir,exist_ok=True)
    write_private_text(f'{cfgdir}/client.ovpn',openvpn_profile_with_local_secrets(profile,requires_auth,requires_key_pass))
    if requires_auth:
        username=str(v['username'] or '').strip(); password=dec(v['password_enc'])
        if not username: raise ValueError('El usuario OpenVPN es obligatorio.')
        validate_config_secret(password,'La contraseña OpenVPN')
        write_private_text(f'{cfgdir}/auth.txt',username+'\n'+password+'\n')
    if requires_key_pass:
        key_pass=dec(v['openvpn_key_pass_enc']); validate_config_secret(key_pass,'La passphrase OpenVPN')
        write_private_text(f'{cfgdir}/askpass.txt',key_pass+'\n')
    gen_access_compose(v,sl)

def ppp_quoted(value, label):
    value=str(value or '')
    if not value or any(ch in value for ch in '\r\n\x00'): raise ValueError(label+' no válido.')
    return '"'+value.replace('\\','\\\\').replace('"','\\"')+'"'

def gen_pptp(v, sl):
    host=str(v['host'] or '').strip()
    if not re.fullmatch(r'[A-Za-z0-9.-]+',host): raise ValueError('Gateway PPTP no válido.')
    username=str(v['username'] or '').strip(); password=dec(v['password_enc'])
    if not username: raise ValueError('El usuario PPTP es obligatorio.')
    validate_config_secret(password,'La contraseña PPTP')
    cfgdir=f'{BASE}/configs/{sl}'; os.makedirs(cfgdir,exist_ok=True)
    write_private_text(f'{cfgdir}/chap-secrets',ppp_quoted(username,'Usuario PPTP')+' * '+ppp_quoted(password,'Contraseña PPTP')+' *\n')
    write_private_text(f'{cfgdir}/ppp-options','''noauth
refuse-eap
refuse-pap
refuse-chap
refuse-mschap
persist
nodetach
maxfail 0
holdoff 5
noipdefault
defaultroute
replacedefaultroute
usepeerdns
name %s
''' % ppp_quoted(username,'Usuario PPTP'))
    start='''#!/bin/sh
set -eu
PPTP_GATEWAY=%s
GW_IP="$(getent ahostsv4 "$PPTP_GATEWAY" | awk 'NR==1 {print $1}')"
test -n "$GW_IP"
OLD_GW="$(ip route show default | awk 'NR==1 {print $3}')"
OLD_DEV="$(ip route show default | awk 'NR==1 {print $5}')"
test -n "$OLD_GW"; test -n "$OLD_DEV"
ip route replace "$GW_IP" via "$OLD_GW" dev "$OLD_DEV"
exec pptp "$PPTP_GATEWAY" file /etc/ppp/options.pptp
''' % ppp_quoted(host,'Gateway PPTP')
    start_path=f'{cfgdir}/start-pptp.sh'; write_private_text(start_path,start); os.chmod(start_path,0o700)
    gen_access_compose(v,sl)

def gen_ssl(v, sl):
    ssl_user=validate_config_secret(v['username'],'El usuario SSL'); ssl_password=validate_config_secret(dec(v['password_enc']),'La contraseña SSL')
    cfg=(f"host = {v['host']}\n"
         f"port = {v['port']}\n"
         f"username = {ssl_user}\n"
         f"password = {ssl_password}\n"
         "set-dns = 0\npppd-use-peerdns = 0\n")
    if dec(v['trusted_cert_enc']): cfg += f"trusted-cert = {dec(v['trusted_cert_enc'])}\n"
    write_private_text(f'{BASE}/configs/{sl}/openfortivpn.conf',cfg)
    compose=f"""services:
  vpn-{sl}:
    image: {runtime_image('ssl')}
    container_name: vpn-{sl}
    labels:
      plantas.vpn.slug: "{sl}"
      plantas.vpn.onboarding: "true"
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/ppp:/dev/ppp
    volumes:
      - ./configs/{sl}/openfortivpn.conf:/etc/openfortivpn/config:ro
      - ./configs/{sl}/haproxy.cfg:/etc/haproxy/haproxy.cfg:ro
    networks:
      - bastion
networks:
  bastion:
    external: true
    name: vpn_bastion_net
"""
    with open(f'{BASE}/sites/{sl}/compose.yml','w') as fh: fh.write(compose)
def write_ipsec_compose(sl,engine):
    compose=f"""services:
  vpn-{sl}:
    image: {runtime_image('ipsec',engine)}
    container_name: vpn-{sl}
    labels:
      plantas.vpn.slug: "{sl}"
      plantas.vpn.onboarding: "true"
    restart: unless-stopped
    privileged: true
    cap_add:
      - NET_ADMIN
    volumes:
      - ./configs/{sl}/ipsec.conf:/etc/ipsec.conf:ro
      - ./configs/{sl}/ipsec.secrets:/etc/ipsec.secrets:ro
      - ./configs/{sl}/haproxy.cfg:/etc/haproxy/haproxy.cfg:ro
    environment:
      VPN_READY_TIMEOUT: '120'
    networks:
      - bastion
networks:
  bastion:
    external: true
    name: vpn_bastion_net
"""
    with open(f'{BASE}/sites/{sl}/compose.yml','w') as fh:fh.write(compose)

def gen_ikev2_eap(v,sl):
    v=dict(v);local=(v.get('local_id') or '').strip();leftid=(local if local.startswith('@') else '@'+local) if local else '%any';leftid_line=('    leftid='+leftid+'\n') if local else ''
    dh_map={'1':'modp768','2':'modp1024','5':'modp1536','14':'modp2048','15':'modp3072','16':'modp4096','17':'modp6144','18':'modp8192','19':'ecp256','20':'ecp384','21':'ecp521'};dh_values=csv_values(v.get('dh_groups')) or [str(v.get('dh_group') or '14')]
    ike_proposals=','.join(expand_ike_proposals(proposal_rows(v,1),dh_values,dh_map))+'!';pfs_enabled=int(v.get('pfs') or 0);pfs_dh=require_mapped(dh_map,v.get('pfs_group') or v.get('dh_group') or '14','Grupo PFS') if pfs_enabled else ''
    esp_proposals=','.join(f"{row['encryption']}-{row['integrity']}"+(f'-{pfs_dh}' if pfs_enabled else '') for row in proposal_rows(v,2))+'!';remote_subnet=','.join(remote_subnets(v));interval=max(1,int(v.get('dpd_retry_interval') or 5));count=max(1,int(v.get('dpd_retry_count') or 3));dpd_lines=(f'    dpddelay={interval}s\n    dpdtimeout={interval*(count+1)}s\n    dpdaction=restart\n' if int(v.get('dpd') or 0) else '');forceencaps='yes' if int(v.get('nat_traversal') or 0) else 'no';eap_identity=strongswan_quote(v['username'],'El usuario EAP')
    conf=f"""config setup
    charondebug="ike 2, cfg 2, chd 2, net 1"

conn plant-ipsec
    auto=add
    keyexchange=ikev2
    type=tunnel
    ike={ike_proposals}
    esp={esp_proposals}
    left=%defaultroute
{leftid_line}    leftauth=eap-mschapv2
    eap_identity={eap_identity}
    leftsourceip=%config
    right={v['host']}
    rightid=%any
    rightauth=psk
    rightsubnet={remote_subnet}
    ikelifetime={v['phase1_lifetime']}s
    lifetime={v['phase2_lifetime']}s
    reauth=no
{dpd_lines}    fragmentation=yes
    forceencaps={forceencaps}
    mobike=no
"""
    psk=strongswan_quote(dec(v['psk_enc']),'La PSK');eap_password=strongswan_quote(dec(v['password_enc']),'La contraseña EAP');sec=f'{leftid} %any : PSK {psk}\n{eap_identity} : EAP {eap_password}\n';write_ipsec_pair(f'{BASE}/configs/{sl}/ipsec.conf',conf,f'{BASE}/configs/{sl}/ipsec.secrets',sec);write_ipsec_compose(sl,'strongswan')

def gen_ikev1_xauth_strongswan(v,sl):
    v=dict(v);local=(v.get('local_id') or '').strip();leftid_line=('    leftid='+local+'\n') if local else '';remote=(v.get('remote_id') or '%any').strip();dh_map={'1':'modp768','2':'modp1024','5':'modp1536','14':'modp2048','15':'modp3072','16':'modp4096','17':'modp6144','18':'modp8192','19':'ecp256','20':'ecp384','21':'ecp521'};dh_values=csv_values(v.get('dh_groups')) or [str(v.get('dh_group') or '14')]
    ike_proposals=','.join(expand_ike_proposals(proposal_rows(v,1),dh_values,dh_map))+'!';pfs_enabled=int(v.get('pfs') or 0);pfs_dh=require_mapped(dh_map,v.get('pfs_group') or v.get('dh_group') or dh_values[0],'Grupo PFS') if pfs_enabled else '';esp_proposals=','.join(f"{row['encryption']}-{row['integrity']}"+(f'-{pfs_dh}' if pfs_enabled else '') for row in proposal_rows(v,2))+'!'
    interval=max(1,int(v.get('dpd_retry_interval') or 5));count=max(1,int(v.get('dpd_retry_count') or 3));dpd_lines=(f'    dpddelay={interval}s\n    dpdtimeout={interval*(count+1)}s\n    dpdaction=restart\n' if int(v.get('dpd') or 0) else '');forceencaps='yes' if int(v.get('nat_traversal') or 0) else 'no';aggressive='yes' if int(v.get('aggressive') or 0) else 'no';modeconfig=v.get('modecfg') or 'pull';xuser=strongswan_quote(v['username'],'El usuario XAuth')
    conf=f"""config setup
    uniqueids=no
    charondebug="ike 1, knl 1, cfg 1"

conn plant-ipsec
    auto=add
    keyexchange=ikev1
    type=tunnel
    aggressive={aggressive}
    authby=xauthpsk
    xauth=client
    xauth_identity={xuser}
    left=%defaultroute
{leftid_line}    leftsourceip=%config
    right={v['host']}
    rightid={remote}
    rightsubnet={','.join(remote_subnets(v))}
    ike={ike_proposals}
    esp={esp_proposals}
    ikelifetime={v['phase1_lifetime']}s
    lifetime={v['phase2_lifetime']}s
{dpd_lines}    forceencaps={forceencaps}
    modeconfig={modeconfig}
"""
    psk=strongswan_quote(dec(v['psk_enc']),'La PSK');xpass=strongswan_quote(dec(v['password_enc']),'La contraseña XAuth');sec=f'%any : PSK {psk}\n{xuser} : XAUTH {xpass}\n';write_ipsec_pair(f'{BASE}/configs/{sl}/ipsec.conf',conf,f'{BASE}/configs/{sl}/ipsec.secrets',sec);write_ipsec_compose(sl,'strongswan')

def gen_ipsec(v, sl):
    if (v['ike_version'] or 'ikev1').lower()=='ikev2': return gen_ikev2_eap(v, sl)
    if (v['ipsec_engine'] if 'ipsec_engine' in v.keys() else 'libreswan')=='strongswan': return gen_ikev1_xauth_strongswan(v, sl)
    is_ikev2=(v['ike_version'] or 'ikev1').lower()=='ikev2'
    remote_id=(v['remote_id'] or '%any')
    local_id=(v['local_id'] or '').strip()
    local_id_line=('    leftid=@'+local_id+'\n' if local_id and not local_id.startswith('@') else ('    leftid='+local_id+'\n' if local_id else ''))
    is_ikev2=(v['ike_version'] or 'ikev1').lower()=='ikev2'
    modepull='    modecfgpull=yes\n' if (v['modecfg'] or 'pull')=='pull' and not is_ikev2 else ''
    ikev2_setting='ikev2=insist' if is_ikev2 else 'ikev2=never'
    auth_lines=('' if is_ikev2 else '    leftxauthclient=yes\n    leftmodecfgclient=yes\n'+modepull+'    leftusername=\"'+v['username']+'\"\n    rightxauthserver=yes\n    rightmodecfgserver=yes\n')
    aggr='no' if is_ikev2 else ('yes' if int(v['aggressive'] or 0) else 'no'); pfs='yes' if int(v['pfs'] or 0) else 'no'; nat='yes' if int(v['nat_traversal'] or 1) else 'no'
    dh_map={'1':'modp768','2':'modp1024','5':'modp1536','14':'modp2048','15':'modp3072','16':'modp4096','17':'modp6144','18':'modp8192','19':'dh19','20':'dh20','21':'dh21'};dh_values=csv_values(v['dh_groups'] if 'dh_groups' in v.keys() else '') or [str(v['dh_group'])]
    if any(group not in dh_map for group in dh_values):raise ValueError('Grupo DH no soportado por Libreswan.')
    auth_map={'sha1':'sha1','sha256':'sha2_256','sha384':'sha2_384','sha512':'sha2_512'};ike=','.join(f"{row['encryption']}-{auth_map[row['integrity']]};{dh_map[group]}" for row in proposal_rows(v,1) for group in dh_values)
    pfs_group=str((v['pfs_group'] if 'pfs_group' in v.keys() else '') or v['dh_group']);pfs_dh=dh_map.get(pfs_group)
    if int(v['pfs'] or 0) and not pfs_dh:raise ValueError('Grupo PFS no soportado por Libreswan.')
    esp=','.join(f"{row['encryption']}-{auth_map[row['integrity']]}"+(f';{pfs_dh}' if int(v['pfs'] or 0) else '') for row in proposal_rows(v,2));networks=remote_subnets(v);remote_subnet_line=('    rightsubnet='+networks[0]) if len(networks)==1 else ('    rightsubnets={'+','.join(networks)+'}')
    dpd_lines=('    dpddelay=30\n    dpdtimeout=120\n    dpdaction=restart\n' if int(v['dpd'] or 0) else '')
    conf=f"""config setup
    uniqueids=no
    protostack=netkey
    plutodebug=none
    ikev1-policy=accept

conn plant-ipsec
    auto=start
    type=tunnel
    authby=secret
    aggrmode={aggr}
    {ikev2_setting}
    left=%defaultroute
{local_id_line}{auth_lines}    right={v['host']}
    rightid={remote_id}
{remote_subnet_line}
    ike={ike}
    phase2alg={esp}
    pfs={pfs}
    ikelifetime={v['phase1_lifetime']}s
    salifetime={v['phase2_lifetime']}s
{dpd_lines}    encapsulation={nat}
"""
    psk=strongswan_quote(dec(v['psk_enc']),'La PSK'); xpass=strongswan_quote(dec(v['password_enc']),'La contraseña XAuth'); xuser=strongswan_quote(v['username'],'El usuario XAuth')
    ipsec_secrets=(f"%any {v['host']} : PSK {psk}\n" f"{xuser} : XAUTH {xpass}\n" f"%any : XAUTH {xpass}\n")
    write_ipsec_pair(f'{BASE}/configs/{sl}/ipsec.conf',conf,f'{BASE}/configs/{sl}/ipsec.secrets',ipsec_secrets)
    compose=f"""services:
  vpn-{sl}:
    image: {runtime_image('ipsec','libreswan')}
    container_name: vpn-{sl}
    labels:
      plantas.vpn.slug: "{sl}"
      plantas.vpn.onboarding: "true"
    restart: unless-stopped
    privileged: true
    cap_add:
      - NET_ADMIN
    volumes:
      - ./configs/{sl}/ipsec.conf:/etc/ipsec.conf:ro
      - ./configs/{sl}/ipsec.secrets:/etc/ipsec.secrets:ro
      - ./configs/{sl}/haproxy.cfg:/etc/haproxy/haproxy.cfg:ro
    environment:
      VPN_READY_TIMEOUT: '120'
    networks:
      - bastion
networks:
  bastion:
    external: true
    name: vpn_bastion_net
"""
    with open(f'{BASE}/sites/{sl}/compose.yml','w') as fh: fh.write(compose)
@app.route('/admin/vpns/<int:i>/generate',methods=['POST'])
@admin
@vpn_mutation_lock
def gen(i):
    try:verify_onboarding_csrf(request.form)
    except ValueError:abort(400)
    if not db().execute('select 1 from vpns where id=?',(i,)).fetchone():abort(404)
    abort(410)

def can_access_equipment(u,eid,plant):
    if u['role']=='admin': return True
    return bool(db().execute('SELECT 1 FROM permissions WHERE user_id=? AND equipment_id=? UNION SELECT 1 FROM plant_permissions WHERE user_id=? AND plant=? LIMIT 1',(u['id'],eid,u['id'],plant)).fetchone())
def guacamole_connection_name(e):
    kind=(e.get('kind') if hasattr(e,'get') else e['kind']) or 'RDP'
    protocol=str(kind).strip().lower()
    if protocol not in {'rdp','vnc'}: raise ValueError('Protocolo Guacamole no válido')
    return f"{protocol}-{int(e['id'])}"

def guacamole_tab_title(e):
    import unicodedata
    value=e.get('plant') if hasattr(e,'get') else e['plant']
    value=unicodedata.normalize('NFKD',str(value or ''))
    value=''.join(ch for ch in value if ch.isascii() and ch.isalnum()).upper()[:64]
    if value: return value
    eid=e.get('id') if hasattr(e,'get') else e['id']
    return (f'RDP{int(eid)}')[:64]


def guacamole_client_url(connection_name,token,tab_title=None):
    from urllib.parse import quote
    import base64,re
    client_id=base64.b64encode((str(connection_name)+'\x00c\x00json').encode()).decode().rstrip('=')
    prefix='/guacamole/'
    if tab_title is not None:
        if not re.fullmatch(r'[A-Z0-9]{1,64}',str(tab_title)):
            raise ValueError('Título de pestaña Guacamole no válido')
        prefix+='?tabTitle='+quote(str(tab_title),safe='')
    return prefix+'#/client/'+quote(client_id,safe='')+'?data='+quote(token,safe='')

@app.route('/equipment/<int:eid>/rdp')
@need
def open_rdp(eid):
    return open_remote(eid,'RDP')

@app.route('/equipment/<int:eid>/vnc')
@need
def open_vnc(eid):
    return open_remote(eid,'VNC')

def open_remote(eid,kind):
    u=me(); e=db().execute('SELECT * FROM equipment WHERE id=? AND active=1',(eid,)).fetchone()
    if not e or e['kind']!=kind: abort(404)
    if not can_access_equipment(u,eid,e['plant']): abort(403)
    if not e['proxy_port'] or not vpn_for_plant(e['plant']): abort(503)
    launches=[]
    for row in db().execute("SELECT * FROM equipment WHERE active=1 AND kind IN ('RDP','VNC') ORDER BY id").fetchall():
        if not can_access_equipment(u,row['id'],row['plant']) or not row['proxy_port']:
            continue
        vpn=vpn_for_plant(row['plant'])
        if vpn:
            launches.append((dict(row),vpn['slug']))
    target=guacamole_connection_name(dict(e))
    token=guacamole_token(u['username'],launches)
    tab_title=guacamole_tab_title(dict(e)) if kind=='RDP' else None
    return redirect(guacamole_client_url(target,token,tab_title))

@app.route('/admin/equipment')
@admin
def eq():
    groups={}
    for row in db().execute("SELECT plant FROM vpns WHERE plant IS NOT NULL AND TRIM(plant)<>'' ORDER BY id"):
        label=normalize_plant_name(row['plant']); groups.setdefault(plant_key(label),{'plant':label,'total':0,'web_total':0,'rdp_total':0,'vnc_total':0})
    for row in db().execute("SELECT plant,COUNT(*) AS total,SUM(CASE WHEN kind='WEB' THEN 1 ELSE 0 END) AS web_total,SUM(CASE WHEN kind='RDP' THEN 1 ELSE 0 END) AS rdp_total,SUM(CASE WHEN kind='VNC' THEN 1 ELSE 0 END) AS vnc_total FROM equipment WHERE plant IS NOT NULL AND TRIM(plant)<>'' GROUP BY plant"):
        label=normalize_plant_name(row['plant']); item=groups.setdefault(plant_key(label),{'plant':label,'total':0,'web_total':0,'rdp_total':0,'vnc_total':0}); item['total']+=row['total'] or 0;item['web_total']+=row['web_total'] or 0;item['rdp_total']+=row['rdp_total'] or 0;item['vnc_total']+=row['vnc_total'] or 0
    plants=sorted(groups.values(),key=lambda x:x['plant'].casefold())
    b="<p class='muted'>Seleccione una planta para consultar, añadir o importar sus equipos.</p><div class='grid'>"
    for counts in plants:
        plant=counts['plant'];label=html.escape(plant);href='/admin/equipment/plant/'+quote(plant,safe='')
        b+=f"<a class='card' href='{href}' style='text-decoration:none;color:inherit'><h2>{label}</h2><p><strong>{counts['total']}</strong> equipos</p><p class='muted'>WEB: {counts['web_total']} · RDP: {counts['rdp_total']} · VNC: {counts['vnc_total']}</p><span class='btn primary'>Ver equipos</span></a>"
    if not plants: b+="<div class='card'><p>No hay plantas configuradas.</p><a class='btn primary' href='/admin/vpns/new'>Añadir VPN/planta</a></div>"
    return page('Equipos por planta',b+'</div>')

@app.route('/admin/equipment/plant/<path:plant>')
@admin
def equipment_by_plant(plant):
    canonical=canonical_plant_name(plant)
    if not canonical: abort(404)
    variants=plant_variants(canonical);marks=','.join('?' for _ in variants)
    rows=db().execute(f'SELECT * FROM equipment WHERE plant IN ({marks}) ORDER BY name',variants).fetchall();qplant=quote(canonical,safe='')
    b=f"<a class=btn href='/admin/equipment'>← Plantas</a><a class='btn primary' href='/admin/equipment/new?plant={qplant}'>Añadir equipo</a><a class='btn primary' href='/admin/equipment/plant/{qplant}/import'>Importar CSV</a>"
    if not rows: return page('Equipos · '+html.escape(canonical),b+"<div class=card><p>No hay equipos en esta planta.</p></div>")
    b+=equipment_tag_filter_controls()+"<div class='card table-card'><div class='table-scroll'><table id='equipment-table'><thead><tr><th>Nombre</th><th>Tipo</th><th>Tags</th><th>Equipo real</th><th>Publicación WEB</th><th>URL</th><th></th></tr></thead><tbody>"
    for e in rows:
        tags=equipment_tag_names(db(),e['id']);tag_filter=','.join(tag.casefold() for tag in tags);tag_badges=equipment_tag_badges(tags)
        if e['kind']=='RDP': access=f"<a class='btn primary' href='/equipment/{e['id']}/rdp' target='_blank' rel='noopener'>Abrir RDP</a>"
        elif e['kind']=='VNC': access=f"<a class='btn primary' href='/equipment/{e['id']}/vnc' target='_blank' rel='noopener'>Abrir VNC</a>"
        else: access=f"<a href='{html.escape(e['public_url'] or '',quote=True)}' target='_blank' rel='noopener'>{html.escape(e['public_url'] or '')}</a>"
        mode=html.escape((e['web_effective_mode'] or 'direct') if e['kind']=='WEB' else '—'); diagnostic=html.escape(e['web_diagnostic'] or '')
        b+=f"<tr data-tags='{html.escape(tag_filter,quote=True)}'><td>{html.escape(e['name'])}</td><td>{html.escape(e['kind'])}</td><td class='equipment-tags'>{tag_badges}</td><td>{html.escape(e['real_ip'])}:{html.escape(str(e['real_port']))}</td><td>{mode}<br><span class='muted'>{diagnostic}</span></td><td class=url>{access}</td><td><a class=btn href=/admin/equipment/{e['id']}/edit>Editar</a><form method=post action=/admin/equipment/{e['id']}/delete style='display:inline'><button class=btn>Eliminar</button></form></td></tr>"
    return page('Equipos · '+html.escape(canonical),b+"</tbody></table></div></div><div id='equipment-filter-empty' class='card tag-filter-empty' hidden>No hay equipos con los tags seleccionados.</div>"+TAG_FILTER_SCRIPT)


@app.route('/admin/equipment/import/template.csv')
@admin
def equipment_import_template():
    content=("nombre;tipo;ip;puerto;ruta;puerto_publico;modo_web;url_publica;descripcion;usuario_rdp;password_rdp;dominio_rdp;remote_app;tags\\r\\n"
             "Web directo;WEB;192.0.2.10;80;/;;direct;;Acceso directo;;;;Scada\\r\\n"
             "Web compatible;WEB;192.0.2.11;80;/;;rewrite_cache;;Reescritura y caché;;;;CCTV\\r\\n"
             "Web automático;WEB;192.0.2.12;80;/;;auto;;Diagnóstico automático;;;;Inversores|SET\\r\\n")
    return Response(content,content_type='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename=plantilla_equipos.csv'})

EQUIPMENT_EXPORT_CODEC='plantas-vpn-safe-v1'
EQUIPMENT_EXPORT_HEADERS=('nombre','tipo','ip','puerto','ruta','url_publica','puerto_publico','modo_web','descripcion','remote_app','vnc_password_enc','vnc_read_only','tags','_csv_codec')
def spreadsheet_safe_csv_cell(value):
    text='' if value is None else str(value)
    if text.startswith("'") or text.lstrip(' \t\r\n').startswith(('=','+','-','@')): return "'"+text
    return text
def spreadsheet_decode_csv_cell(value):
    text='' if value is None else str(value)
    if text.startswith("''"): return text[1:]
    if text.startswith("'") and text[1:].lstrip(' \t\r\n').startswith(('=','+','-','@')): return text[1:]
    return text

def equipment_export_csv(rows,tags_by_id):
    stream=io.StringIO(newline='')
    writer=csv.writer(stream,delimiter=';',lineterminator='\r\n')
    writer.writerow(EQUIPMENT_EXPORT_HEADERS)
    for e in rows:
        values=(e['name'],e['kind'],e['real_ip'],e['real_port'],e['path'] or '/',e['public_url'] or '',e['proxy_port'] or public_port_from_url(e['public_url']) or '',e['web_mode'] if e['web_mode'] in {'auto','direct','rewrite_cache'} else 'auto',e['description'] or '',e['rdp_remote_app'] or '',(e['vnc_password_enc'] or '') if e['kind']=='VNC' else '',e['vnc_read_only'] or 0 if e['kind']=='VNC' else 0,'|'.join(tags_by_id.get(e['id'],[])))
        writer.writerow([*(spreadsheet_safe_csv_cell(value) for value in values),EQUIPMENT_EXPORT_CODEC])
    return '﻿'+stream.getvalue()

@app.route('/admin/equipment/plant/<path:plant>/export.csv')
@admin
def equipment_bulk_export(plant):
    plant=canonical_plant_name(plant)
    if not plant: abort(404)
    rows=db().execute('SELECT * FROM equipment WHERE plant=? AND active=1 ORDER BY id',(plant,)).fetchall()
    tags={row['id']:equipment_tag_names(db(),row['id']) for row in rows}
    content=equipment_export_csv(rows,tags)
    filename='equipos_'+slug(plant)+'.csv'
    return Response(content,content_type='text/csv; charset=utf-8',headers={'Content-Disposition':f'attachment; filename={filename}'})

@app.route('/admin/equipment/plant/<path:plant>/import',methods=['GET','POST'])
@admin
def equipment_bulk_import(plant):
    plant=canonical_plant_name(plant)
    if not plant: abort(404)
    qplant=quote(plant,safe='')
    body=f"""<a class=btn href='/admin/equipment/plant/{qplant}'>← Equipos de {html.escape(plant)}</a><div class=card><h2>Importar equipos</h2><p>Suba un CSV UTF-8 separado por coma o punto y coma. Todos los equipos se añadirán a <strong>{html.escape(plant)}</strong>.</p><p>En <code>modo_web</code> use: <strong>auto, direct, rewrite_cache</strong>. En modo auto cada equipo WEB se analiza desde la VPN de esta planta antes de publicar.</p><p>Las columnas obligatorias son: nombre, tipo, ip, puerto y modo_web. Puerto público vacío se asigna automáticamente.</p><p>Para filas VNC, <code>vnc_password_enc</code> debe contener el ciphertext generado por este panel; nunca introduzca la contraseña en claro. La exportación del panel ya incluye ese valor cifrado y <code>vnc_read_only</code>.</p><p>La columna opcional <code>tags</code> admite: <strong>Scada, Trackers, Inversores, CCTV, SET</strong>. Separe varios tags con <code>|</code>.</p><a class='btn' href='/admin/equipment/import/template.csv'>Descargar plantilla CSV</a><a class='btn' href='/admin/equipment/plant/{qplant}/export.csv'>Exportar equipos CSV</a><form method=post enctype='multipart/form-data'><label>Archivo CSV</label><input type=file name=csv_file accept='.csv,text/csv' required><button class='btn primary'>Validar, importar y publicar</button></form></div>"""
    if request.method=='GET': return page('Importar equipos · '+plant,body)
    policy=(request.form.get('duplicate_policy') or '').strip();batch_token=(request.form.get('batch_token') or '').strip()
    if batch_token:
        if policy not in {'keep','overwrite'}: flash('Seleccione cómo tratar los equipos duplicados'); return page('Importar equipos · '+plant,body),400
        batch=db().execute('SELECT * FROM equipment_import_batches WHERE token=? AND user_id=? AND plant=?',(batch_token,session['uid'],plant)).fetchone()
        if not batch or int(batch['created_ts'])<int(time.time())-900:
            if batch: db().execute('DELETE FROM equipment_import_batches WHERE token=?',(batch_token,));db().commit()
            flash('La confirmación de importación ha caducado. Vuelva a cargar el CSV.'); return page('Importar equipos · '+plant,body),400
        raw=dec(batch['csv_enc']).encode('utf-8')
    else:
        upload=request.files.get('csv_file')
        if not upload or not upload.filename: flash('Seleccione un archivo CSV'); return page('Importar equipos · '+plant,body),400
        raw=upload.read()
    used=set()
    for row in db().execute('SELECT proxy_port,public_url FROM equipment'):
        port=row['proxy_port'] or public_port_from_url(row['public_url'])
        if port: used.add(int(port))
    variants=plant_variants(plant);marks=','.join('?' for _ in variants);existing={}
    for row in db().execute(f'SELECT * FROM equipment WHERE plant IN ({marks})',variants):
        key=equipment_ip_key(row['real_ip'])
        if key in existing: flash(f"Hay varios equipos existentes con la IP {html.escape(row['real_ip'])}; resuelva esa duplicidad antes de importar.");return page('Importar equipos · '+plant,body),400
        existing[key]=row
    try:
        parsed=parse_bulk_csv(raw,plant,used,existing)
        duplicates=[(item,existing[item['_ip_key']]) for item in parsed if item['_ip_key'] in existing]
        if duplicates and not policy:
            token=secrets.token_urlsafe(32);conn=db();conn.execute('DELETE FROM equipment_import_batches WHERE created_ts<?',(int(time.time())-900,));conn.execute('INSERT INTO equipment_import_batches(token,user_id,plant,csv_enc,created_ts) VALUES(?,?,?,?,?)',(token,session['uid'],plant,enc(raw.decode('utf-8-sig')),int(time.time())));conn.commit()
            rows=''.join(f"<tr><td>{html.escape(new['real_ip'])}</td><td>{html.escape(old['name'])}</td><td>{html.escape(new['name'])}</td></tr>" for new,old in duplicates)
            confirm=f"<a class=btn href='/admin/equipment/plant/{qplant}/import'>← Cancelar</a><div class=card><h2>IP ya existente</h2><p>Se han encontrado equipos de esta planta con la misma IP. Elija cómo tratarlos:</p><table><tr><th>IP</th><th>Equipo original</th><th>Equipo del CSV</th></tr>{rows}</table><form method=post><input type=hidden name=batch_token value='{html.escape(token,quote=True)}'><button class='btn primary' name=duplicate_policy value=overwrite>Sobrescribir duplicados</button><button class=btn name=duplicate_policy value=keep>Mantener originales</button></form></div>"
            return page('Confirmar equipos duplicados · '+html.escape(plant),confirm),409
        if policy=='keep': parsed=[item for item in parsed if item['_ip_key'] not in existing]
        if not parsed:
            if batch_token: db().execute('DELETE FROM equipment_import_batches WHERE token=?',(batch_token,));db().commit()
            flash('No se realizaron cambios: se mantuvieron todos los equipos originales.');return redirect('/admin/equipment/plant/'+qplant)
        next_id=int(db().execute('SELECT COALESCE(MAX(id),0)+1 FROM equipment').fetchone()[0]); finalized=[]
        for item in parsed:
            old=existing.get(item.pop('_ip_key')) if policy=='overwrite' else None;eid=old['id'] if old else next_id
            if not old: next_id+=1
            finalized.append((eid,finalize_web_settings(item,eid,old),old))
    except ValueError as ex:
        flash(str(ex)); return page('Importar equipos · '+plant,body),400
    conn=db(); conn.execute('SAVEPOINT equipment_bulk_import')
    try:
        now=datetime.now().isoformat(timespec='seconds')
        for eid,f,old in finalized:
            public_url=f'/equipment/{eid}/{f["kind"].lower()}' if f['kind'] in {'RDP','VNC'} else f['public_url']
            values=(f['plant'],f['name'],f['kind'],f['real_ip'],f['real_port'],f['path'],public_url,f['description'],f['proxy_port'],f['rdp_username_enc'],f['rdp_password_enc'],f['rdp_domain_enc'],f['rdp_remote_app'],f['vnc_password_enc'],f['vnc_read_only'],f['web_mode'],f['web_effective_mode'],f['web_diagnostic'],f['web_proxy_port'])
            if old: conn.execute('UPDATE equipment SET plant=?,name=?,kind=?,real_ip=?,real_port=?,path=?,public_url=?,description=?,proxy_port=?,rdp_username_enc=?,rdp_password_enc=?,rdp_domain_enc=?,rdp_remote_app=?,vnc_password_enc=?,vnc_read_only=?,web_mode=?,web_effective_mode=?,web_diagnostic=?,web_proxy_port=? WHERE id=?',values+(eid,))
            else: conn.execute('INSERT INTO equipment(id,plant,name,kind,real_ip,real_port,path,public_url,description,active,created_at,proxy_port,rdp_username_enc,rdp_password_enc,rdp_domain_enc,rdp_remote_app,vnc_password_enc,vnc_read_only,web_mode,web_effective_mode,web_diagnostic,web_proxy_port) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(eid,)+values[:8]+(1,now)+values[8:])
            set_equipment_tags(conn,eid,f['tags'])
        ports=publish_plant(plant)
        if batch_token: conn.execute('DELETE FROM equipment_import_batches WHERE token=?',(batch_token,))
        conn.execute('RELEASE SAVEPOINT equipment_bulk_import');conn.commit()
    except Exception as ex:
        try: conn.execute('ROLLBACK TO SAVEPOINT equipment_bulk_import');conn.execute('RELEASE SAVEPOINT equipment_bulk_import');conn.commit()
        except Exception: conn.rollback()
        try: publish_plant(plant)
        except Exception: pass
        flash('No se importó ningún equipo porque no se pudo aplicar la configuración: '+str(ex)); return page('Importar equipos · '+plant,body),500
    counts={mode:sum(1 for _,f,_ in finalized if f['kind']=='WEB' and f['web_effective_mode']==mode) for mode in ('direct','rewrite_cache')}
    flash(f"Importación completada: {len(finalized)} equipos. WEB directos: {counts['direct']}; WEB con reescritura/caché: {counts['rewrite_cache']}. Puertos publicados: "+(', '.join(map(str,ports)) if ports else 'ninguno'))
    return redirect('/admin/equipment/plant/'+qplant)

def plant_options(selected=''):
    vals=[];seen=set();selected=canonical_plant_name(selected) or normalize_plant_name(selected)
    for r in db().execute("SELECT plant FROM vpns UNION SELECT plant FROM equipment ORDER BY plant"):
        key=plant_key(r[0])
        if key and key not in seen: seen.add(key);vals.append(canonical_plant_name(r[0]) or normalize_plant_name(r[0]))
    if selected and plant_key(selected) not in seen: vals.insert(0,selected)
    return ''.join(f"<option value='{html.escape(p,quote=True)}' {'selected' if p==selected else ''}>{html.escape(p)}</option>" for p in vals)
def public_port_from_url(url):
    m=re.search(r':(\d+)(?:/|$)', url or '')
    return int(m.group(1)) if m else None
def next_public_port():
    used=set()
    for r in db().execute("SELECT public_url,proxy_port FROM equipment"):
        p=r['proxy_port'] or public_port_from_url(r['public_url'])
        if p: used.add(int(p))
    for root,dirs,files in os.walk(f'{BASE}/sites'):
        for fn in files:
            if fn.endswith(('.yml','.yaml')):
                try:
                    txt=open(os.path.join(root,fn)).read()
                    for m in re.finditer(r':(\d+):\d+', txt): used.add(int(m.group(1)))
                except Exception: pass
    p=8081
    while p in used: p+=1
    return p
def ef(e=None, rdp_import=False, locked_plant=None):
    e=dict(e) if e else {'kind':'WEB','active':1,'plant':''}
    import_field="<label>Importar archivo .RDP</label><input name='rdp_file' type='file' accept='.rdp,application/octet-stream'><p class='muted'>Seleccione la planta y cargue el .RDP: al guardar se extraen el host, puerto, nombre y alias RemoteApp. Las credenciales se mantienen en el panel.</p>" if rdp_import else ''
    esc=lambda v: html.escape(str(v or ''),quote=True)
    kind=e.get('kind') if e.get('kind') in {'WEB','RDP','VNC'} else 'WEB'
    opts=''.join(f"<option {'selected' if kind==k else ''}>{k}</option>" for k in ['WEB','RDP','VNC'])
    popts=plant_options(e.get('plant',''))
    if locked_plant:
        locked_plant=locked_plant.strip(); plant_field=f"<label>Planta</label><div class='card'><strong>{esc(locked_plant)}</strong></div><input type='hidden' name='plant' value='{esc(locked_plant)}'>"
    else: plant_field=f"<label>Planta</label><select name='plant' required>{popts}</select>"
    pub_port=e.get('proxy_port') or public_port_from_url(e.get('public_url','')) or ''
    web_mode=e.get('web_mode') if e.get('web_mode') in {'auto','direct','rewrite_cache'} else 'auto'
    web_mode_options=[('auto','Automático (recomendado)'),('direct','Directo'),('rewrite_cache','Reescritura y caché')]
    wmopts=''.join(f"<option value='{value}' {'selected' if web_mode==value else ''}>{label}</option>" for value,label in web_mode_options)
    raw_tags=e.get('tags',equipment_tag_names(db(),e['id']) if e.get('id') else [])
    if isinstance(raw_tags,str): raw_tags=re.split(r'[|,]',raw_tags)
    tag_lookup={name.casefold():name for name in EQUIPMENT_TAG_CATALOG};selected_tags={tag_lookup[str(value).strip().casefold()] for value in (raw_tags or []) if str(value).strip().casefold() in tag_lookup}
    tag_picker="<fieldset class='tag-picker'><legend>Tags</legend><p class='muted'>Seleccione una o varias categorías.</p><div class='tag-options'>"+''.join(f"<label class='tag-option tag-{equipment_tag_slug(name)}'><input type='checkbox' name='tags' value='{esc(name)}' {'checked' if name in selected_tags else ''}><span>{esc(name)}</span></label>" for name in EQUIPMENT_TAG_CATALOG)+"</div></fieldset>"
    web_diag=(f"<p class='muted'><strong>Último diagnóstico:</strong> {esc(e.get('web_diagnostic'))} · Modo aplicado: {esc(e.get('web_effective_mode'))}</p>" if e.get('web_diagnostic') else '')
    ruser=dec(e.get('rdp_username_enc','')); rdomain=dec(e.get('rdp_domain_enc',''))
    return f"""<form class='card' method='post' enctype='multipart/form-data' id='equipment-form'>
{plant_field}
<label>Nombre</label><input name='name' value='{esc(e.get('name'))}' required>
<label>Tipo</label><select name='kind' id='equipment-kind'>{opts}</select>
{tag_picker}
<label>IP real del equipo</label><input name='real_ip' value='{esc(e.get('real_ip'))}' required>
<label>Puerto real</label><input name='real_port' id='real-port' value='{esc(e.get('real_port'))}' placeholder='80/443 WEB; 3389 RDP; 5900 VNC'>
<div id='web-fields'><label>Tratamiento web</label><select name='web_mode'>{wmopts}</select><p class='muted'>Automático analiza redirecciones y URLs privadas; puede forzar acceso directo o reescritura y caché.</p>{web_diag}<label>Ruta web</label><input name='path' value='{esc(e.get('path') or '/')}'><label>Puerto público bastión</label><input name='public_port' value='{esc(pub_port)}' placeholder='vacío = automático'><label>URL pública/enlace</label><input name='public_url' value='{esc(e.get('public_url'))}' placeholder='vacío = se genera automáticamente'></div>
<div id='rdp-fields'><h3>Credenciales RDP</h3><p class='muted'>Se cifran en el panel y se entregan a Guacamole mediante un token cifrado de 60 segundos. Si ya existe contraseña, dejarla vacía la conserva.</p>{import_field}<label>Usuario RDP</label><input name='rdp_username' value='{esc(ruser)}' autocomplete='off' placeholder='usuario o usuario@dominio'><label>Contraseña RDP</label><input name='rdp_password' type='password' autocomplete='new-password' placeholder='vacío = conservar la existente'><label>Dominio (opcional)</label><input name='rdp_domain' value='{esc(rdomain)}' autocomplete='off'><label>Alias RemoteApp (opcional)</label><input name='rdp_remote_app' value='{esc(e.get('rdp_remote_app',''))}' autocomplete='off' placeholder='Ej.: GPM+Híjar3'><p class='muted'>Solo si el equipo publica una RemoteApp; introduzca el alias sin los dos caracteres | iniciales.</p></div>
<div id='vnc-fields'><h3>Acceso VNC</h3><p class='muted'>La contraseña se cifra en el panel y se entrega a Guacamole mediante un token cifrado de 60 segundos. Si ya existe contraseña, dejarla vacía la conserva.</p><label>Contraseña VNC</label><input name='vnc_password' type='password' autocomplete='new-password' placeholder='vacío = conservar la existente'><label><input name='vnc_read_only' type='checkbox' value='1' {'checked' if e.get('vnc_read_only') else ''} style='width:auto'> Solo lectura</label></div>
<label>Descripción</label><textarea name='description'>{esc(e.get('description'))}</textarea><button class='btn primary'>Guardar y publicar</button></form>
<script>(function(){{const k=document.getElementById('equipment-kind'),w=document.getElementById('web-fields'),r=document.getElementById('rdp-fields'),v=document.getElementById('vnc-fields'),p=document.getElementById('real-port');function sync(){{const kind=k.value;w.style.display=kind==='WEB'?'block':'none';r.style.display=kind==='RDP'?'block':'none';v.style.display=kind==='VNC'?'block':'none';p.placeholder=kind==='RDP'?'vacío = 3389':kind==='VNC'?'vacío = 5900':'80 para HTTP o 443 para HTTPS';}}k.addEventListener('change',sync);sync();}})();</script>"""
def vpn_for_plant(plant):
    key=plant_key(plant)
    for row in db().execute("SELECT * FROM vpns WHERE active=1 AND onboarding_state IN ('active','online') ORDER BY id"):
        if plant_key(row['plant'])==key: return row
    return None
def parse_rdp_content(raw):
    if not isinstance(raw,(bytes,bytearray)) or not raw: raise ValueError('El archivo .RDP está vacío')
    if len(raw)>65536: raise ValueError('El archivo .RDP supera el límite de 64 KB')
    if raw.startswith(b'\xff\xfe'): text=raw.decode('utf-16')
    elif raw.startswith(b'\xfe\xff'): text=raw.decode('utf-16')
    else:
        try: text=raw.decode('utf-8-sig')
        except UnicodeDecodeError: text=raw.decode('utf-16le')
    values={}
    for line in text.splitlines():
        parts=line.split(':',2)
        if len(parts)==3: values[parts[0].strip().lower()]=parts[2].strip()
    address=(values.get('full address') or values.get('alternate full address') or '').strip()
    if not address: raise ValueError('El archivo .RDP no contiene “full address”')
    host=address; embedded_port=''
    if address.startswith('[') and ']:' in address:
        host,embedded_port=address[1:].split(']:',1)
    elif address.count(':')==1:
        candidate,maybe_port=address.rsplit(':',1)
        if maybe_port.isdigit(): host,embedded_port=candidate,maybe_port
    host=host.strip()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}',host): raise ValueError('Host del archivo .RDP inválido')
    port=(values.get('server port') or embedded_port or '3389').strip()
    if not port.isdigit() or not 1<=int(port)<=65535: raise ValueError('Puerto del archivo .RDP inválido')
    remote_app=(values.get('remoteapplicationprogram') or values.get('alternate shell') or '').strip()
    if remote_app.startswith('||'): remote_app=remote_app[2:]
    if len(remote_app)>255 or any(ord(ch)<32 for ch in remote_app): raise ValueError('Alias RemoteApp del archivo .RDP inválido')
    name=(values.get('remoteapplicationname') or remote_app or 'RDP '+host).strip()
    if len(name)>255 or any(ord(ch)<32 for ch in name): raise ValueError('Nombre del archivo .RDP inválido')
    return {'kind':'RDP','name':name,'real_ip':host,'real_port':port,'rdp_remote_app':remote_app}

def imported_rdp_form(form, upload):
    values=dict(form)
    if not upload or not upload.filename: return values
    if not upload.filename.lower().endswith('.rdp'): raise ValueError('Seleccione un archivo con extensión .RDP')
    values.update(parse_rdp_content(upload.read(65537)))
    return values

def equipment_values(f, old=None):
    old=dict(old) if old else {}
    kind=(f.get('kind') or 'WEB').upper()
    if kind not in {'WEB','RDP','VNC'}: raise ValueError('El tipo de equipo debe ser WEB, RDP o VNC')
    web_mode=(f.get('web_mode') or old.get('web_mode') or 'auto').strip().lower() if kind=='WEB' else 'direct'
    if web_mode not in {'auto','direct','rewrite_cache'}: raise ValueError('El tratamiento web debe ser automático, directo o reescritura y caché')
    plant=(f.get('plant') or '').strip(); name=(f.get('name') or '').strip(); real_ip=(f.get('real_ip') or '').strip()
    if not plant or not name or not real_ip: raise ValueError('Planta, nombre e IP real son obligatorios')
    tags=normalize_equipment_tags(f.get('tags',[]))
    default_port='80' if kind=='WEB' else ('3389' if kind=='RDP' else '5900')
    real_port=(f.get('real_port') or default_port).strip()
    if not real_port.isdigit() or not 1 <= int(real_port) <= 65535: raise ValueError('Puerto real inválido; use un número entre 1 y 65535')
    requested=(f.get('public_port') or '').strip()
    if requested and (not requested.isdigit() or not 1<=int(requested)<=65535): raise ValueError('Puerto de proxy inválido')
    proxy_port=int(requested or old.get('proxy_port') or public_port_from_url(old.get('public_url','')) or next_public_port())
    if kind=='RDP':
        ruser=(f.get('rdp_username') or '').strip(); rpass=f.get('rdp_password') or ''; rdomain=(f.get('rdp_domain') or '').strip(); remote_app=(f.get('rdp_remote_app') or '').strip()
        user_enc=enc(ruser) if ruser else old.get('rdp_username_enc','')
        pass_enc=enc(rpass) if rpass else old.get('rdp_password_enc','')
        domain_enc=enc(rdomain) if rdomain else old.get('rdp_domain_enc','')
        if bool(user_enc) != bool(pass_enc): raise ValueError('Para RDP indique usuario y contraseña, o deje ambos vacíos')
        if len(remote_app)>255 or any(ord(ch)<32 for ch in remote_app): raise ValueError('Alias RemoteApp inválido')
        remote_app=remote_app[2:] if remote_app.startswith('||') else remote_app
        return dict(plant=plant,name=name,kind=kind,real_ip=real_ip,real_port=real_port,path='',public_url='',proxy_port=proxy_port,web_mode=web_mode,rdp_username_enc=user_enc,rdp_password_enc=pass_enc,rdp_domain_enc=domain_enc,rdp_remote_app=remote_app,vnc_password_enc='',vnc_read_only=0,description=f.get('description',''),tags=tags)
    if kind=='VNC':
        vpass=f.get('vnc_password') or ''
        imported_enc=(f.get('vnc_password_enc') or '').strip()
        if imported_enc:
            if len(imported_enc)>4096 or not dec(imported_enc): raise ValueError('El ciphertext VNC no es válido; exporte la contraseña desde este panel')
            pass_enc=imported_enc
        else:
            pass_enc=enc(vpass) if vpass else old.get('vnc_password_enc','')
        read_only=1 if str(f.get('vnc_read_only') or '').lower() in {'1','true','on','yes'} else 0
        return dict(plant=plant,name=name,kind=kind,real_ip=real_ip,real_port=real_port,path='',public_url='',proxy_port=proxy_port,web_mode=web_mode,rdp_username_enc='',rdp_password_enc='',rdp_domain_enc='',rdp_remote_app='',vnc_password_enc=pass_enc,vnc_read_only=read_only,description=f.get('description',''),tags=tags)
    path=(f.get('path') or '/').strip()
    pub_url=(f.get('public_url') or '').strip()
    if not pub_url:
        suffix=path if path else '/'
        if not suffix.startswith('/'): suffix='/'+suffix
        pub_url=f'{PUBLIC_ORIGIN}:{proxy_port}{suffix}'
    return dict(plant=plant,name=name,kind=kind,real_ip=real_ip,real_port=real_port,path=path,public_url=pub_url,proxy_port=proxy_port,web_mode=web_mode,rdp_username_enc='',rdp_password_enc='',rdp_domain_enc='',rdp_remote_app='',vnc_password_enc='',vnc_read_only=0,description=f.get('description',''),tags=tags)
def equipment_ip_key(value):
    value=str(value or '').strip()
    try: return ipaddress.ip_address(value).compressed.casefold()
    except ValueError: return value.casefold()
def parse_bulk_csv(raw, plant, used_ports=None, existing_by_ip=None):
    if not isinstance(raw,(bytes,bytearray)) or not raw: raise ValueError('El archivo CSV está vacío')
    if len(raw)>1048576: raise ValueError('El archivo CSV supera el límite de 1 MB')
    try: text=raw.decode('utf-8-sig')
    except UnicodeDecodeError: raise ValueError('El CSV debe estar codificado en UTF-8')
    header_line=text.splitlines()[0] if text.splitlines() else ''
    delimiter=';' if header_line.count(';')>header_line.count(',') else ','
    reader=csv.DictReader(io.StringIO(text),delimiter=delimiter,quotechar='"')
    if not reader.fieldnames: raise ValueError('El CSV no contiene cabeceras')
    headers={str(x or '').strip().lower():x for x in reader.fieldnames}
    required={'nombre','tipo','ip','puerto','modo_web'};missing=required-set(headers)
    if missing: raise ValueError('Faltan columnas obligatorias: '+', '.join(sorted(missing)))
    used=set(int(x) for x in (used_ports or set())); existing_by_ip=existing_by_ip or {};result=[];seen_ips=set()
    def value(row,key):
        text=row.get(headers.get(key,'')) or ''
        codec=(row.get(headers.get('_csv_codec','')) or '').strip()
        return spreadsheet_decode_csv_cell(text) if codec==EQUIPMENT_EXPORT_CODEC else text.strip()
    for line,row in enumerate(reader,2):
        if not any(str(v or '').strip() for v in row.values()): continue
        if len(result)>=200: raise ValueError('El CSV supera el máximo de 200 equipos')
        csv_kind=value(row,'tipo').upper()
        vnc_cipher=value(row,'vnc_password_enc')
        if csv_kind=='VNC' and (len(vnc_cipher)>4096 or not dec(vnc_cipher)):
            raise ValueError(f'Fila {line}: se requiere un ciphertext VNC válido exportado por este panel')
        real_ip=value(row,'ip');ip_key=equipment_ip_key(real_ip)
        if ip_key in seen_ips: raise ValueError(f'Fila {line}: la IP {real_ip} está repetida dentro del CSV')
        seen_ips.add(ip_key);old=existing_by_ip.get(ip_key);old_port=(old['proxy_port'] or public_port_from_url(old['public_url'])) if old else None
        requested=value(row,'puerto_publico')
        if requested:
            if not requested.isdigit() or not 1<=int(requested)<=65535: raise ValueError(f'Fila {line}: puerto público inválido')
            public_port=int(requested)
            if public_port in used and not (old_port and public_port==int(old_port)): raise ValueError(f'Fila {line}: el puerto público {public_port} ya está en uso')
        elif old_port: public_port=int(old_port)
        else:
            public_port=8081
            while public_port in used: public_port+=1
            if public_port>65535: raise ValueError('No quedan puertos públicos disponibles')
        used.add(public_port)
        form={'plant':plant,'name':value(row,'nombre'),'kind':value(row,'tipo'),'real_ip':real_ip,'real_port':value(row,'puerto'),'path':value(row,'ruta') or '/','public_port':str(public_port),'public_url':value(row,'url_publica'),'web_mode':value(row,'modo_web') or 'auto','description':value(row,'descripcion'),'rdp_username':value(row,'usuario_rdp'),'rdp_password':value(row,'password_rdp'),'rdp_domain':value(row,'dominio_rdp'),'rdp_remote_app':value(row,'remote_app'),'vnc_password_enc':vnc_cipher,'vnc_read_only':value(row,'vnc_read_only'),'tags':value(row,'tags')}
        try:
            item=equipment_values(form,old)
            if (row.get(headers.get('_csv_codec','')) or '').strip()==EQUIPMENT_EXPORT_CODEC: item['name']=value(row,'nombre')
            if old and not value(row,'tags').strip(): item['tags']=equipment_tag_names(db(),old['id'])
            item['_ip_key']=ip_key;result.append(item)
        except ValueError as ex: raise ValueError(f'Fila {line}: {ex}')
    if not result: raise ValueError('El CSV no contiene equipos')
    return result

GUAC_JSON_KEY=os.environ.get('GUAC_JSON_KEY','')
def guacamole_token(username,launches,now_ms=None):
    import base64, hashlib, hmac, json
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
    if not re.fullmatch(r'[0-9a-fA-F]{32}',GUAC_JSON_KEY or ''): raise RuntimeError('GUAC_JSON_KEY no está configurada correctamente')
    now_ms=int(time.time()*1000) if now_ms is None else int(now_ms)
    connections={}
    for e,vpn_slug in launches:
        protocol=str(e.get('kind') or 'RDP').lower()
        params={'hostname':'vpn-'+vpn_slug,'port':str(e['proxy_port'])}
        if protocol=='rdp':
            params.update({'ignore-cert':'true','security':'any','resize-method':'display-update'})
            ruser=dec(e.get('rdp_username_enc') or ''); rpass=dec(e.get('rdp_password_enc') or ''); domain=dec(e.get('rdp_domain_enc') or '')
            if ruser: params['username']=ruser
            if rpass: params['password']=rpass
            if domain: params['domain']=domain
            remote_app=(e.get('rdp_remote_app') or '').strip()
            if remote_app: params['remote-app']='||'+remote_app.lstrip('|')
        elif protocol=='vnc':
            vpass=dec(e.get('vnc_password_enc') or '')
            if vpass: params['password']=vpass
            if e.get('vnc_read_only'): params['read-only']='true'
        else: raise ValueError('Protocolo Guacamole no válido')
        connections[guacamole_connection_name(e)]={'protocol':protocol,'parameters':params}
    data={'username':username,'expires':now_ms+60000,'connections':connections}
    payload=json.dumps(data,separators=(',',':')).encode(); key=bytes.fromhex(GUAC_JSON_KEY)
    signed=hmac.new(key,payload,hashlib.sha256).digest()+payload
    padder=PKCS7(128).padder(); padded=padder.update(signed)+padder.finalize()
    encryptor=Cipher(algorithms.AES(key),modes.CBC(bytes(16))).encryptor()
    return base64.b64encode(encryptor.update(padded)+encryptor.finalize()).decode()

def web_redirect_rules(real_ip, real_port, public_url):
    scheme='https' if str(public_url or '').lower().startswith('https://') else 'http'
    target=re.escape(str(real_ip))
    port=re.escape(str(real_port))
    return ("    http-request set-var(txn.public_host) req.hdr(Host)\n"
            f"    http-response replace-header Location ^https?://{target}(?::{port})?(/.*)?$ {scheme}://%[var(txn.public_host)]\\1\n"
            )

def finalize_web_settings(values, equipment_id, old=None):
    result=dict(values); old=dict(old) if old else {}
    if result['kind']!='WEB':
        result.update(web_effective_mode='direct',web_diagnostic='',web_proxy_port=None); return result
    vpn=vpn_for_plant(result['plant'])
    if not vpn: raise ValueError(f"No hay VPN configurada para la planta {result['plant']}")
    analysis=probe_web_equipment(vpn['slug'],result['real_ip'],result['real_port'],result['web_mode'])
    listener=None
    if analysis['effective_mode']=='rewrite_cache':
        listener=old.get('web_proxy_port') or (18000+int(equipment_id))
        if int(listener)>65535: raise ValueError('No quedan listeners internos disponibles para el proxy WEB')
    result.update(web_effective_mode=analysis['effective_mode'],web_diagnostic=analysis['diagnostic'],web_proxy_port=listener)
    return result

def probe_web_equipment(slug, real_ip, real_port, requested_mode, runner=subprocess.run):
    if requested_mode in {'direct','rewrite_cache'}:
        return resolve_web_mode(requested_mode,{'effective_mode':'direct','diagnostic':''})
    scheme='https' if str(real_port)=='443' else 'http'; url=f'{scheme}://{real_ip}:{real_port}/'
    base=['docker','exec',f'vpn-{slug}','curl','-k','-sS','--connect-timeout','5','--max-time','20']
    headers=runner(base+['-D','-','-o','/dev/null',url],text=True,capture_output=True,timeout=30)
    body=runner(base+['-L','--max-redirs','2','-H','Accept-Encoding:','--range','0-524287',url],text=True,capture_output=True,timeout=30)
    if headers.returncode!=0 or body.returncode!=0:
        detail=(headers.stderr or body.stderr or 'sin respuesta').strip()[-300:]
        raise ValueError(f'No se pudo analizar el equipo WEB desde la VPN {slug}: {detail}')
    return resolve_web_mode('auto',analyze_web_probe(headers.stdout,body.stdout,real_ip,real_port))

def analyze_web_probe(headers, body, real_ip, real_port):
    """Classify only concrete private-origin evidence; latency alone never enables rewriting."""
    origin=rf"https?://{re.escape(str(real_ip))}(?::{re.escape(str(real_port))})?"
    reasons=[]
    if re.search(rf"<base\b[^>]*href\s*=\s*['\"]{origin}(?:/|['\"])",body or '',re.I): reasons.append('base HTML privada')
    if re.search(rf"^Location:\s*{origin}(?:/|$)",headers or '',re.I|re.M): reasons.append('redirección privada')
    absolute=len(re.findall(rf"{origin}/",body or '',re.I))
    if absolute and 'base HTML privada' not in reasons: reasons.append(f'{absolute} URL absolutas privadas')
    mode='rewrite_cache' if reasons else 'direct'
    return {'effective_mode':mode,'diagnostic':('; '.join(reasons) if reasons else 'Sin URLs privadas; publicación directa')}

def resolve_web_mode(requested, analysis):
    if requested=='direct': return {'effective_mode':'direct','diagnostic':'Modo directo forzado por el administrador'}
    if requested=='rewrite_cache': return {'effective_mode':'rewrite_cache','diagnostic':'Reescritura y caché forzadas por el administrador'}
    return dict(analysis)

def row_value(row, key, default=None):
    try: return row[key]
    except (KeyError,IndexError,TypeError): return default

def render_webfix_config(slug, rows):
    blocks=[]
    for e in rows:
        if row_value(e,'kind')!='WEB' or row_value(e,'web_effective_mode')!='rewrite_cache': continue
        eid=int(row_value(e,'id')); ip=str(row_value(e,'real_ip')); port=str(row_value(e,'real_port')); listen=int(row_value(e,'web_proxy_port'))
        scheme='https' if port=='443' else 'http'; origin=f'{scheme}://{ip}' + ('' if port in {'80','443'} else f':{port}')
        ssl='    proxy_ssl_verify off;\n' if scheme=='https' else ''
        extra_origin='' if origin in {f'http://{ip}',f'https://{ip}'} else f"        sub_filter '{origin}/' '$scheme://$http_host/';"
        blocks.append(f'''proxy_cache_path /var/cache/nginx/eq_{eid} levels=1:2 keys_zone=eq_{eid}_static:10m max_size=250m inactive=7d use_temp_path=off;
server {{
    listen {listen};
    server_name _;
    proxy_http_version 1.1;
    proxy_set_header Host {ip};
    proxy_set_header X-Forwarded-Host $http_host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Accept-Encoding "";
{ssl}    proxy_redirect {origin}/ $scheme://$http_host/;
    location ~* \\.(?:css|js|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot)$ {{
        proxy_set_header Cookie "";
        proxy_cache eq_{eid}_static;
        proxy_cache_key "$proxy_host$request_uri";
        proxy_cache_valid 200 7d;
        proxy_cache_valid 404 5m;
        proxy_hide_header Set-Cookie;
        add_header X-Webfix-Cache $upstream_cache_status always;
        proxy_pass {scheme}://{ip}:{port};
    }}
    location / {{
        proxy_buffering on;
        sub_filter_once off;
        sub_filter_types text/css application/javascript;
        sub_filter 'http://{ip}/' '$scheme://$http_host/';
        sub_filter 'https://{ip}/' '$scheme://$http_host/';
{extra_origin}
        proxy_pass {scheme}://{ip}:{port};
    }}
}}
''')
    return '\n'.join(blocks)

def web_backend_target(plant, e):
    if row_value(e,'kind')=='WEB' and row_value(e,'web_effective_mode')=='rewrite_cache' and row_value(e,'web_proxy_port'):
        return f"127.0.0.1:{int(row_value(e,'web_proxy_port'))}"
    return f"{row_value(e,'real_ip')}:{row_value(e,'real_port')}"

def render_haproxy_for_plant(plant):
    rows=db().execute('SELECT * FROM equipment WHERE plant=? AND active=1 ORDER BY id',(plant,)).fetchall()
    cfg='global\n    log stdout format raw local0\n\ndefaults\n    log global\n    timeout connect 10s\n    timeout client 120s\n    timeout server 120s\n\n'
    exposed=[]
    for e in rows:
        if e['kind'] not in {'WEB','RDP','VNC'}: continue
        p=e['proxy_port'] or public_port_from_url(e['public_url'])
        if not p or not e['real_ip'] or not e['real_port']: continue
        if e['kind']=='WEB': exposed.append(int(p))
        name=re.sub('[^a-zA-Z0-9_]+','_',f"{e['plant']}_{e['name']}_{e['id']}").lower()
        mode='tcp' if e['kind']=='WEB' and e['web_effective_mode']=='direct' else ('http' if e['kind']=='WEB' else 'tcp')
        sslopt=' ssl verify none' if e['kind']=='WEB' and str(e['real_port'])=='443' else ''
        redirect_rules=web_redirect_rules(e['real_ip'],e['real_port'],e['public_url']) if e['kind']=='WEB' and mode=='http' else ''
        cfg+=f'frontend {name}\n    bind *:{p}\n    mode {mode}\n{redirect_rules}    default_backend {name}_backend\n\nbackend {name}_backend\n    mode {mode}\n    server target {web_backend_target(plant,e)}{sslopt}\n\n'
    return cfg, sorted(set(exposed))
def update_webfix_compose_text(text, slug, enabled):
    service_re=rf"\n  webfix-{re.escape(slug)}:\n(?:(?!\n  [A-Za-z0-9_-]+:\n|\nnetworks:\n).)*"
    text=re.sub(service_re,'',text,flags=re.S)
    text=re.sub(rf"^  {re.escape(slug)}_web_cache:\s*$\n?",'',text,flags=re.M)
    if not enabled: return text
    block=f"""
  webfix-{slug}:
    image: sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10
    container_name: webfix-{slug}
    restart: unless-stopped
    depends_on:
      - vpn-{slug}
    network_mode: 'service:vpn-{slug}'
    volumes:
      - ./configs/{slug}/webfix.conf:/etc/nginx/conf.d/default.conf:ro
      - {slug}_web_cache:/var/cache/nginx
"""
    marker='\nnetworks:\n'
    if marker not in text: raise ValueError('El compose de la planta no contiene la sección networks')
    text=text.replace(marker,block+marker,1)
    if re.search(r'^volumes:\s*$',text,re.M): text=re.sub(r'^(volumes:\s*)$',rf"\1\n  {slug}_web_cache:",text,count=1,flags=re.M)
    else: text=text.rstrip()+f"\n\nvolumes:\n  {slug}_web_cache:\n"
    return text

def update_compose_ports_text(txt,ports):
 txt=re.sub(r'    ports:\n(?:      - .*\n)+','',txt)
 if ports:
  block='    ports:\n'+''.join(f'      - 0.0.0.0:{port}:{port}\n' for port in ports);marker='    cap_add:\n      - NET_ADMIN\n';txt=txt.replace(marker,marker+block,1) if marker in txt else txt.replace('    restart: unless-stopped\n','    restart: unless-stopped\n'+block,1)
 return txt
def update_compose_ports(sl,ports):
 p=f'{BASE}/sites/{sl}/compose.yml'
 with open(p,encoding='utf-8') as fh:txt=fh.read()
 with open(p,'w',encoding='utf-8') as fh:fh.write(update_compose_ports_text(txt,ports))
def publish_plant(plant):
 v=vpn_for_plant(plant)
 if not v:raise Exception(f'No hay VPN activa para la planta {plant}')
 with vpn_slug_lock(v['slug']):return _publish_plant_locked(plant)
def _publish_plant_locked(plant):
 v=vpn_for_plant(plant)
 if not v:raise Exception(f'No hay VPN activa para la planta {plant}')
 sl=v['slug'];config_dir=f'{BASE}/configs/{sl}';compose_path=f'{BASE}/sites/{sl}/compose.yml';haproxy_path=f'{config_dir}/haproxy.cfg';webfix_path=f'{config_dir}/webfix.conf'
 if not os.path.isfile(compose_path):raise Exception('Falta el Compose propietario de la VPN activa.')
 current=db().execute("SELECT active,onboarding_state,onboarding_revision FROM vpns WHERE id=?",(v['id'],)).fetchone() if 'id' in v else None
 if 'id' in v and (not current or not int(current['active'] or 0) or current['onboarding_state'] not in {'active','online'}):raise Exception('La VPN dejó de estar activa antes de publicar.')
 revision=int(current['onboarding_revision'] or 0) if current else 0;rows=db().execute('SELECT * FROM equipment WHERE plant=? AND active=1 ORDER BY id',(plant,)).fetchall();cfg,ports=render_haproxy_for_plant(plant);rewrite=[e for e in rows if e['kind']=='WEB' and e['web_effective_mode']=='rewrite_cache'];has_webfix=bool(rewrite)
 with open(compose_path,encoding='utf-8') as fh:old_compose=fh.read()
 new_compose=update_webfix_compose_text(update_compose_ports_text(old_compose,ports),sl,has_webfix);new_webfix=render_webfix_config(sl,rewrite) if has_webfix else None
 paths=(haproxy_path,webfix_path,compose_path)
 def snapshot_file(path):
  if not os.path.exists(path):return False,b''
  with open(path,'rb') as fh:return True,fh.read()
 snapshot={path:snapshot_file(path) for path in paths};token=secrets.token_urlsafe(18);temps={haproxy_path:haproxy_path+'.stage-'+token,compose_path:compose_path+'.stage-'+token}
 if has_webfix:temps[webfix_path]=webfix_path+'.stage-'+token
 live_mutated=False;old_has_webfix=snapshot[webfix_path][0] and f'webfix-{sl}:' in old_compose
 def write_stage(path,content):
  with open(path,'w',encoding='utf-8') as fh:fh.write(content);fh.flush();os.fsync(fh.fileno())
 def restore_files():
  for p,(existed,data) in snapshot.items():
   if existed:
    tmp=p+'.rollback-'+token
    with open(tmp,'wb') as fh:fh.write(data);fh.flush();os.fsync(fh.fileno())
    os.replace(tmp,p)
   elif os.path.exists(p):os.remove(p)
 try:
  write_stage(temps[haproxy_path],cfg);write_stage(temps[compose_path],new_compose)
  if has_webfix:write_stage(temps[webfix_path],new_webfix)
  compose_cmd=['docker','compose','--project-directory',BASE,'-f',f'{BASE}/docker-compose.yml','-f',temps[compose_path]];check=subprocess.run([*compose_cmd,'config','-q'],cwd=BASE,text=True,capture_output=True,timeout=60)
  if check.returncode!=0:raise Exception('Configuración Compose staged inválida.')
  if has_webfix:
   check=subprocess.run(['docker','run','--rm','--pull','never','--network','none','-v',f'{temps[webfix_path]}:/etc/nginx/conf.d/default.conf:ro','sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10','nginx','-t'],cwd=BASE,text=True,capture_output=True,timeout=60)
   if check.returncode!=0:raise Exception('Configuración Nginx staged inválida.')
  if 'id' in v:
   cur=db().execute("SELECT active,onboarding_state,onboarding_revision FROM vpns WHERE id=?",(v['id'],)).fetchone()
   if not cur or not int(cur['active'] or 0) or cur['onboarding_state'] not in {'active','online'} or int(cur['onboarding_revision'] or 0)!=revision:raise Exception('La VPN cambió durante la preparación de publicación.')
  live_mutated=True;os.replace(temps[haproxy_path],haproxy_path);os.replace(temps[compose_path],compose_path)
  if has_webfix:os.replace(temps[webfix_path],webfix_path)
  elif os.path.exists(webfix_path):os.remove(webfix_path)
  live_cmd=['docker','compose','--project-directory',BASE,'-f',f'{BASE}/docker-compose.yml','-f',compose_path];services=[f'vpn-{sl}']+([f'webfix-{sl}'] if has_webfix else []);r=subprocess.run([*live_cmd,'up','-d','--no-deps','--force-recreate','--pull','never','--no-build',*services],cwd=BASE,text=True,capture_output=True,timeout=240)
  if r.returncode!=0:raise Exception('Falló la publicación del runtime exacto.')
  if not has_webfix:
   rm=subprocess.run(['docker','rm','-f',f'webfix-{sl}'],cwd=BASE,text=True,capture_output=True,timeout=60)
   if rm.returncode not in (0,1):raise Exception('No se pudo retirar el helper webfix anterior.')
  return ports
 except Exception as publish_error:
  if live_mutated:
   try:restore_files()
   except Exception as rollback_error:raise Exception('Falló la publicación y no se pudieron restaurar sus archivos.') from rollback_error
   services=[f'vpn-{sl}']+([f'webfix-{sl}'] if old_has_webfix else []);rollback=['docker','compose','--project-directory',BASE,'-f',f'{BASE}/docker-compose.yml','-f',compose_path,'up','-d','--no-deps','--force-recreate','--pull','never','--no-build',*services];rb=subprocess.run(rollback,cwd=BASE,text=True,capture_output=True,timeout=240)
   if rb.returncode!=0:raise Exception('Falló la publicación y también el rollback del runtime anterior.') from publish_error
   if not old_has_webfix:
    probe=subprocess.run(['docker','inspect',f'webfix-{sl}'],cwd=BASE,text=True,capture_output=True,timeout=30)
    if probe.returncode==0:
     removed=subprocess.run(['docker','rm','-f',f'webfix-{sl}'],cwd=BASE,text=True,capture_output=True,timeout=60)
     if removed.returncode!=0:raise Exception('El rollback no pudo retirar el webfix nuevo.') from publish_error
  raise
 finally:
  for p in temps.values():
   try:os.remove(p)
   except FileNotFoundError:pass

@app.route('/admin/equipment/new',methods=['GET','POST'])
@admin
def eqnew():
    locked_raw=(request.args.get('plant') or '').strip();locked=canonical_plant_name(locked_raw) if locked_raw else ''
    if locked_raw and not locked: abort(404)
    if request.method=='POST':
        form=request.form.to_dict();form['tags']=request.form.getlist('tags')
        if locked: form['plant']=locked
        try:
            canonical=canonical_plant_name(form.get('plant'))
            if not canonical: raise ValueError('Seleccione una planta válida.')
            form['plant']=canonical
            form=imported_rdp_form(form,request.files.get('rdp_file'))
            form['plant']=canonical
            f=equipment_values(form)
            eid=db().execute('SELECT COALESCE(MAX(id),0)+1 FROM equipment').fetchone()[0]
            f=finalize_web_settings(f,eid)
        except ValueError as ex: flash(str(ex)); return page('Añadir equipo',ef(form,rdp_import=True,locked_plant=locked or None)),400
        conn=db();conn.execute('SAVEPOINT equipment_create')
        try:
            conn.execute('INSERT INTO equipment(id,plant,name,kind,real_ip,real_port,path,public_url,description,active,created_at,proxy_port,rdp_username_enc,rdp_password_enc,rdp_domain_enc,rdp_remote_app,vnc_password_enc,vnc_read_only,web_mode,web_effective_mode,web_diagnostic,web_proxy_port) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(eid,f['plant'],f['name'],f['kind'],f['real_ip'],f['real_port'],f['path'],f['public_url'],f['description'],1,datetime.now().isoformat(timespec='seconds'),f['proxy_port'],f['rdp_username_enc'],f['rdp_password_enc'],f['rdp_domain_enc'],f['rdp_remote_app'],f['vnc_password_enc'],f['vnc_read_only'],f['web_mode'],f['web_effective_mode'],f['web_diagnostic'],f['web_proxy_port']))
            if f['kind'] in {'RDP','VNC'}:conn.execute('UPDATE equipment SET public_url=? WHERE id=?',(f"/equipment/{eid}/{f['kind'].lower()}",eid))
            set_equipment_tags(conn,eid,f['tags']);ports=publish_plant(f['plant']);conn.execute('RELEASE SAVEPOINT equipment_create');conn.commit();flash('Equipo guardado y acceso aplicado. '+(f"Diagnóstico WEB: {f['web_diagnostic']}. " if f['kind']=='WEB' else '')+'Puertos WEB publicados: '+(', '.join(map(str,ports)) if ports else 'ninguno'))
        except Exception as ex:
            try:conn.execute('ROLLBACK TO SAVEPOINT equipment_create');conn.execute('RELEASE SAVEPOINT equipment_create');conn.commit()
            except Exception:conn.rollback()
            flash('No se guardó el equipo porque la publicación falló: '+str(ex));return page('Añadir equipo',ef(form,rdp_import=True,locked_plant=locked or None)),500
        return redirect('/admin/equipment/plant/'+quote(f['plant'],safe=''))
    initial={'plant':locked} if locked else None
    return page('Añadir equipo',ef(initial,rdp_import=True,locked_plant=locked or None))

@app.route('/admin/equipment/<int:i>/edit',methods=['GET','POST'])
@admin
def eqedit(i):
    e=db().execute('SELECT * FROM equipment WHERE id=?',(i,)).fetchone()
    if not e: abort(404)
    if request.method=='POST':
        oldplant=e['plant']
        try:
            form=request.form.to_dict();form['tags']=request.form.getlist('tags');canonical=canonical_plant_name(form.get('plant'))
            if not canonical: raise ValueError('Seleccione una planta válida.')
            form['plant']=canonical;f=equipment_values(form,e)
            f=finalize_web_settings(f,i,e)
        except ValueError as ex: flash(str(ex)); return page('Editar equipo',ef(dict(e)|form)),400
        public_url=f"/equipment/{i}/{f['kind'].lower()}" if f['kind'] in {'RDP','VNC'} else f['public_url']
        conn=db();conn.execute('SAVEPOINT equipment_edit')
        try:
            conn.execute('UPDATE equipment SET plant=?,name=?,kind=?,real_ip=?,real_port=?,path=?,public_url=?,description=?,proxy_port=?,rdp_username_enc=?,rdp_password_enc=?,rdp_domain_enc=?,rdp_remote_app=?,vnc_password_enc=?,vnc_read_only=?,web_mode=?,web_effective_mode=?,web_diagnostic=?,web_proxy_port=? WHERE id=?',(f['plant'],f['name'],f['kind'],f['real_ip'],f['real_port'],f['path'],public_url,f['description'],f['proxy_port'],f['rdp_username_enc'],f['rdp_password_enc'],f['rdp_domain_enc'],f['rdp_remote_app'],f['vnc_password_enc'],f['vnc_read_only'],f['web_mode'],f['web_effective_mode'],f['web_diagnostic'],f['web_proxy_port'],i));set_equipment_tags(conn,i,f['tags'])
            if oldplant!=f['plant']:publish_plant(oldplant)
            ports=publish_plant(f['plant']);conn.execute('RELEASE SAVEPOINT equipment_edit');conn.commit();flash('Equipo actualizado y acceso aplicado. '+(f"Diagnóstico WEB: {f['web_diagnostic']}. " if f['kind']=='WEB' else '')+'Puertos WEB publicados: '+(', '.join(map(str,ports)) if ports else 'ninguno'))
        except Exception as ex:
            try:conn.execute('ROLLBACK TO SAVEPOINT equipment_edit');conn.execute('RELEASE SAVEPOINT equipment_edit');conn.commit()
            except Exception:conn.rollback()
            for p in {oldplant,f['plant']}:
                try:publish_plant(p)
                except Exception:pass
            flash('No se actualizó el equipo porque la publicación falló: '+str(ex));return page('Editar equipo',ef(e)),500
        return redirect('/admin/equipment/plant/'+quote(f['plant'],safe=''))
    return page('Editar equipo',ef(e))

@app.route('/admin/equipment/<int:i>/delete',methods=['POST'])
@admin
def eqdelete(i):
    conn=db();e=conn.execute('SELECT * FROM equipment WHERE id=?',(i,)).fetchone()
    if not e:abort(404)
    plant=e['plant'];conn.execute('SAVEPOINT equipment_delete')
    try:
        conn.execute('DELETE FROM permissions WHERE equipment_id=?',(i,));conn.execute('DELETE FROM equipment_tags WHERE equipment_id=?',(i,));conn.execute('DELETE FROM equipment WHERE id=?',(i,));ports=publish_plant(plant);conn.execute('RELEASE SAVEPOINT equipment_delete');conn.commit();flash('Equipo eliminado y redirecciones actualizadas. Puertos publicados: '+(', '.join(map(str,ports)) if ports else 'ninguno'))
    except Exception as ex:
        try:conn.execute('ROLLBACK TO SAVEPOINT equipment_delete');conn.execute('RELEASE SAVEPOINT equipment_delete');conn.commit()
        except Exception:conn.rollback()
        try:publish_plant(plant)
        except Exception:pass
        flash('No se eliminó el equipo porque la publicación falló: '+str(ex))
    return redirect('/admin/equipment/plant/'+quote(plant,safe=''))

@app.route('/admin/users')
@admin
def users():
    rows=db().execute('SELECT * FROM users').fetchall(); b="<a class='btn primary' href=/admin/users/new>Nuevo usuario</a><table><tr><th>User</th><th>Rol</th><th></th></tr>"
    for u in rows: b+=f"<tr><td>{u['username']}</td><td>{u['role']}</td><td><a class=btn href=/admin/users/{u['id']}/edit>Permisos</a></td></tr>"
    return page('Usuarios',b+'</table>')
def uf(u=None):
    plants=[r[0] for r in db().execute('SELECT DISTINCT plant FROM equipment ORDER BY plant')]; eqs=db().execute('SELECT * FROM equipment ORDER BY plant,name').fetchall(); ap=set(); ae=set()
    if u: ap={r['plant'] for r in db().execute('SELECT plant FROM plant_permissions WHERE user_id=?',(u['id'],))}; ae={r['equipment_id'] for r in db().execute('SELECT equipment_id FROM permissions WHERE user_id=?',(u['id'],))}
    b=f"<form class=card method=post><label>Usuario</label><input name=username value='{u['username'] if u else ''}'><label>Password</label><input name=password type=password><label>Rol</label><select name=role><option value=operator>operator</option><option value=admin>admin</option></select><h3>Permisos por planta</h3>"
    for p in plants: b+=f"<label><input type=checkbox name=plant value='{p}' {'checked' if p in ap else ''} style='width:auto'> {p}</label>"
    b+='<h3>Permisos por equipo</h3>'
    for e in eqs: b+=f"<label><input type=checkbox name=equip value='{e['id']}' {'checked' if e['id'] in ae else ''} style='width:auto'> {e['plant']} - {e['name']}</label>"
    return b+"<button class='btn primary'>Guardar</button></form>"
@app.route('/admin/users/new',methods=['GET','POST'])
@admin
def unew():
    if request.method=='POST':
        f=request.form; cur=db().execute('INSERT INTO users(username,password_hash,role,active,created_at) VALUES(?,?,?,?,?)',(f['username'],generate_password_hash(f['password']),f['role'],1,datetime.now().isoformat(timespec='seconds'))); uid=cur.lastrowid
        for p in request.form.getlist('plant'): db().execute('INSERT INTO plant_permissions(user_id,plant) VALUES(?,?)',(uid,p))
        for e in request.form.getlist('equip'): db().execute('INSERT INTO permissions(user_id,equipment_id) VALUES(?,?)',(uid,e))
        db().commit(); return redirect('/admin/users')
    return page('Nuevo usuario',uf())
@app.route('/admin/users/<int:i>/edit',methods=['GET','POST'])
@admin
def uedit(i):
    u=db().execute('SELECT * FROM users WHERE id=?',(i,)).fetchone()
    if request.method=='POST':
        f=request.form; db().execute('UPDATE users SET username=?,role=? WHERE id=?',(f['username'],f['role'],i))
        if f.get('password'): db().execute('UPDATE users SET password_hash=? WHERE id=?',(generate_password_hash(f['password']),i))
        db().execute('DELETE FROM permissions WHERE user_id=?',(i,)); db().execute('DELETE FROM plant_permissions WHERE user_id=?',(i,))
        for p in request.form.getlist('plant'): db().execute('INSERT INTO plant_permissions(user_id,plant) VALUES(?,?)',(i,p))
        for e in request.form.getlist('equip'): db().execute('INSERT INTO permissions(user_id,equipment_id) VALUES(?,?)',(i,e))
        db().commit(); return redirect('/admin/users')
    return page('Editar usuario',uf(u))
