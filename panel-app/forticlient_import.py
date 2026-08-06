from __future__ import annotations

import ipaddress
import re
from typing import Iterable
from defusedxml import ElementTree as ET

MAX_FORTICLIENT_BYTES=1024*1024
MAX_PROFILES=64
MAX_DEPTH=24
MAX_NODES=20000

class FortiClientProfileError(ValueError):
    pass

def _fail(message):
    raise FortiClientProfileError(message)

def _local(element):
    return str(element.tag).rsplit('}',1)[-1]

def _child(element,name):
    if element is None:return None
    return next((x for x in list(element) if _local(x)==name),None)

def _children(element,name):
    return [] if element is None else [x for x in list(element) if _local(x)==name]

def _text(element,name=None,default=''):
    node=_child(element,name) if name else element
    return ((node.text or '').strip() if node is not None else default)

def _bool(element,name,default=False):
    value=_text(element,name,'1' if default else '0').lower()
    if value not in {'0','1'}:_fail('El perfil contiene un valor booleano no válido.')
    return value=='1'

def _int(element,name,minimum,maximum,default=None):
    raw=_text(element,name,'' if default is None else str(default))
    try:value=int(raw)
    except (TypeError,ValueError):_fail('El perfil contiene un valor numérico no válido.')
    if not minimum<=value<=maximum:_fail('El perfil contiene un valor numérico fuera de rango.')
    return value

def _safe_text(value,label,maximum=512):
    value=str(value or '').strip()
    if not value or len(value)>maximum or any(ord(x)<32 or ord(x)==127 for x in value):_fail(label+' no válido.')
    return value

def _identity(element,name):
    value=_text(element,name)
    if not value or value.startswith('EncX '):return ''
    return _safe_text(value,'Identificador IPsec',255)

def parse_endpoint(text,default_port):
    value=_safe_text(text,'Gateway VPN',512)
    if '://' in value or any(x in value for x in '/?#@') or re.search(r'\s',value):_fail('Gateway VPN no válido.')
    host='';port=str(default_port)
    if value.startswith('['):
        match=re.fullmatch(r'\[([^]]+)\](?::([0-9]+))?',value)
        if not match:_fail('Gateway VPN no válido.')
        host,explicit=match.groups();port=explicit or port
        try:ipaddress.IPv6Address(host)
        except ValueError:_fail('Gateway VPN no válido.')
    elif value.count(':')==1:
        host,port=value.rsplit(':',1)
    elif value.count(':')>1:
        host=value
        try:ipaddress.IPv6Address(host)
        except ValueError:_fail('Gateway VPN no válido.')
    else:host=value
    if not port.isdigit() or not 1<=int(port)<=65535:_fail('Puerto VPN fuera de rango.')
    try:ipaddress.ip_address(host)
    except ValueError:
        if len(host)>253 or not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*',host):_fail('Gateway VPN no válido.')
    return host,port

ENC={'AES128':'aes128','AES256':'aes256','3DES':'3des'}
INTEGRITY={'SHA1':'sha1','SHA256':'sha256','SHA384':'sha384','SHA512':'sha512'}
DH={'1','2','5','14','15','16','17','18','19','20','21'}

def normalize_proposal(text):
    parts=[x.strip().upper() for x in str(text or '').split('|')]
    if len(parts)!=2 or parts[0] not in ENC or parts[1] not in INTEGRITY:_fail('El perfil usa una propuesta criptográfica no soportada.')
    return {'encryption':ENC[parts[0]],'integrity':INTEGRITY[parts[1]]}

def _proposals(parent):
    container=_child(parent,'proposals');out=[]
    for node in _children(container,'proposal'):
        proposal=normalize_proposal(_text(node))
        if proposal not in out:out.append(proposal)
    if not out:_fail('El perfil no declara propuestas criptográficas.')
    return out

def _dh_groups(text):
    out=[]
    for item in re.split(r'[;,]',str(text or '')):
        item=item.strip()
        if not item:continue
        if item not in DH:_fail('El perfil usa un grupo DH no soportado.')
        if item not in out:out.append(item)
    if not out:_fail('El perfil no declara grupos DH.')
    return out

def _source(root):
    return {'format':'forticlient-xml','version':_text(root,'version') or _text(root,'forticlient_version'),'forticlient_version':_text(root,'forticlient_version'),'exported_by_version':_text(root,'exported_by_version'),'partial_configuration':_text(root,'partial_configuration'),'os_version':_text(root,'os_version'),'os_architecture':_text(root,'os_architecture')}

def _reject_scripts(connection):
    for node in connection.iter():
        if _local(node)=='script' and not list(node) and _text(node):_fail('El perfil contiene scripts y no puede importarse automáticamente.')

def _parse_ssl(connection,source):
    _reject_scripts(connection)
    if _bool(connection,'sso_enabled') or _bool(connection,'use_external_browser'):_fail('El perfil SSL requiere SSO o navegador externo y no está soportado.')
    certificate=_child(connection,'certificate')
    for node in certificate.iter() if certificate is not None else ():
        if _local(node)=='pattern' and _text(node) not in {'','*'}:_fail('El perfil SSL requiere selección de certificado y no está soportado.')
    host,port=parse_endpoint(_text(connection,'server'),443)
    return {'kind':'ssl','profile_name':_safe_text(_text(connection,'name'),'Nombre de perfil',160),'host':host,'port':port,'auth_method':'username-credential','secret_requirements':['login_name','login_credential'],'certificate_pin_required':True,'source':dict(source)}

def _remote_subnets(ipsec):
    excludes=_child(ipsec,'ipv4_split_exclude_networks')
    if excludes is not None and any(_text(n) or list(n) for n in list(excludes)):_fail('El perfil usa exclusiones split-tunnel no soportadas.')
    out=[];container=_child(ipsec,'remote_networks')
    for network in _children(container,'network'):
        addr=_text(network,'addr');mask=_text(network,'mask')
        if ':' in addr:
            if addr not in {'::','::/0'}:_fail('Los selectores IPv6 no están soportados en este flujo.')
            continue
        try:value=str(ipaddress.ip_network(addr+'/'+mask,strict=False))
        except ValueError:_fail('El perfil contiene una red remota no válida.')
        if value not in out:out.append(value)
    return out or ['0.0.0.0/0']

def _parse_ipsec(connection,source):
    _reject_scripts(connection)
    ike=_child(connection,'ike_settings');child=_child(connection,'ipsec_settings')
    if ike is None or child is None:_fail('El perfil IPsec está incompleto.')
    version=_text(ike,'version')
    if version not in {'1','2'}:_fail('La versión IKE no está soportada.')
    if _text(ike,'authentication_method').casefold()!='preshared key':_fail('El perfil IPsec no usa PSK y no está soportado.')
    xauth=_child(ike,'xauth')
    if not _bool(xauth,'enabled'):_fail('El perfil IPsec no declara autenticación de usuario compatible.')
    port=_int(ike,'udp_port',1,65535,500);host,port=parse_endpoint(_text(ike,'server'),port)
    mode=_text(ike,'mode','main').lower()
    if version=='1' and mode not in {'main','aggressive'}:_fail('El modo de intercambio IKEv1 no está soportado.')
    dh_groups=_dh_groups(_text(ike,'dhgroup'))
    phase1_lifetime=_int(ike,'key_life',60,604800)
    if _text(child,'key_life_type','seconds').lower()!='seconds':_fail('Solo se admite lifetime de Phase 2 expresado en segundos.')
    phase2_lifetime=_int(child,'key_life_seconds',60,604800)
    pfs=_bool(child,'pfs');pfs_group=_text(child,'dhgroup').strip()
    if pfs and pfs_group not in DH:_fail('El perfil usa un grupo PFS no soportado.')
    mode_config=_bool(ike,'mode_config') or _bool(child,'use_vip')
    return {'kind':'ipsec','profile_name':_safe_text(_text(connection,'name'),'Nombre de perfil',160),'host':host,'port':port,'ike_version':'ikev'+version,'exchange_mode':(mode if version=='1' else 'ikev2'),'auth_method':('psk-xauth' if version=='1' else 'psk-eap-mschapv2'),'engine':'strongswan','phase1_proposals':_proposals(ike),'dh_groups':dh_groups,'phase1_lifetime':phase1_lifetime,'phase2_proposals':_proposals(child),'phase2_lifetime':phase2_lifetime,'pfs_enabled':pfs,'pfs_group':(pfs_group if pfs else ''),'nat_traversal':_bool(ike,'nat_traversal',True),'dpd_enabled':_bool(ike,'dpd',True),'dpd_retry_count':_int(ike,'dpd_retry_count',0,100,3),'dpd_retry_interval':_int(ike,'dpd_retry_interval',1,3600,5),'mode_config':mode_config,'request_virtual_ip':_bool(child,'use_vip') or mode_config,'local_id':_identity(ike,'localid'),'remote_id':_identity(ike,'peerid'),'remote_subnets':_remote_subnets(child),'secret_requirements':['psk','login_name','login_credential'],'source':dict(source)}

def parse_forticlient_backup(raw):
    if not isinstance(raw,(bytes,bytearray)) or not raw or len(raw)>MAX_FORTICLIENT_BYTES:_fail('El archivo FortiClient está vacío o supera el límite permitido.')
    data=bytes(raw)
    if b'\0' in data:_fail('El archivo FortiClient contiene datos no válidos.')
    try:text=data.decode('utf-8-sig')
    except UnicodeDecodeError:_fail('El archivo FortiClient debe usar UTF-8.')
    lowered=text.lower()
    if any(marker in lowered for marker in ('<!doctype','<!entity','<xi:include','<xinclude')):_fail('El XML FortiClient contiene construcciones no permitidas.')
    try:root=ET.fromstring(text)
    except Exception:_fail('No se pudo analizar el XML FortiClient.')
    if _local(root)!='forticlient_configuration':_fail('El archivo no es una configuración FortiClient compatible.')
    nodes=0
    def walk(node,depth):
        nonlocal nodes
        nodes+=1
        if depth>MAX_DEPTH or nodes>MAX_NODES:_fail('La estructura XML FortiClient supera los límites permitidos.')
        if _local(node).lower() in {'include','fallback'} and 'xinclude' in str(node.tag).lower():_fail('El XML FortiClient contiene inclusiones no permitidas.')
        for child in list(node):walk(child,depth+1)
    walk(root,1)
    vpn=_child(root,'vpn');source=_source(root);profiles=[]
    for kind,parser in (('sslvpn',_parse_ssl),('ipsecvpn',_parse_ipsec)):
        section=_child(vpn,kind);connections=_child(section,'connections')
        for connection in _children(connections,'connection'):
            profiles.append(parser(connection,source))
            if len(profiles)>MAX_PROFILES:_fail('El archivo contiene demasiados perfiles VPN.')
    if not profiles:_fail('No se encontraron perfiles VPN compatibles.')
    return profiles
