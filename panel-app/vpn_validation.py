from __future__ import annotations
import json
from dataclasses import dataclass
import ipaddress,re,os
from pathlib import Path
from vpn_runtime import runtime_image,remote_subnets
DEFAULT_VALIDATION_DENY_CIDRS=('127.0.0.0/8','169.254.0.0/16','100.64.0.0/10')
def validation_deny_networks():
 raw=os.environ.get('VALIDATION_DENY_CIDRS',' '.join(DEFAULT_VALIDATION_DENY_CIDRS))
 return [ipaddress.ip_network(value) for value in raw.replace(',',' ').split() if value]
@dataclass(frozen=True)
class ValidationEvidence:
 container_running:bool=False
 daemon_running:bool=False
 ike_established:bool=False
 child_installed:bool=False
 routes_ok:bool=False
 xfrm_ok:bool=False
 target_ok:bool=False
 peer_replied:bool=False
 auth_failed:bool=False
 proposal_failed:bool=False
 vip_ok:bool=True
 stable:bool=True
 target_tcp_ok:bool=False
 traffic_out:bool=False
 traffic_in:bool=False
@dataclass(frozen=True)
class ValidationResult:
 state:str
 stage:str
 code:str
 public_message:str
 retryable:bool=False
def _result(state,stage,code,message,retryable=False):return ValidationResult(state,stage,code,message,retryable)
def classify_evidence(vpn_type,evidence,raw_diagnostics=''):
 e=evidence;kind=str(vpn_type.get('vpn_type')) if hasattr(vpn_type,'get') else str(vpn_type);need_vip=bool(hasattr(vpn_type,'get') and str(vpn_type.get('modecfg') or '').lower()=='pull');has_target=bool(hasattr(vpn_type,'get') and str(vpn_type.get('validation_target_ip') or ''))
 if not e.container_running:return _result('offline','runtime','container_not_running','El contenedor aislado no está en ejecución.',True)
 if not e.stable:return _result('offline','runtime','runtime_changed','El contenedor cambió durante la validación.',True)
 if not e.daemon_running:return _result('offline','runtime','daemon_not_running','El proceso VPN no está disponible.',True)
 if e.auth_failed:return _result('auth_failed','ike','auth_failed','El peer rechazó la autenticación. Revise las credenciales.',False)
 if e.proposal_failed:return _result('proposal_failed','ike','proposal_failed','El peer rechazó las propuestas criptográficas.',False)
 if kind!='ipsec':
  if not e.ike_established:return _result('offline','tunnel','tunnel_missing','La interfaz del túnel todavía no está disponible.',True)
  if not e.routes_ok:return _result('installed','routes','route_missing','El túnel existe, pero la ruta del destino no usa su interfaz.',True)
  if not e.target_ok:
   if e.traffic_out and e.traffic_in and not e.target_tcp_ok:return _result('installed','target','target_tcp_unreachable','El target responde por la VPN, pero el puerto TCP configurado no acepta conexiones.',True)
   return _result('installed','target','target_unreachable','El destino no responde con tráfico por el túnel.',True)
  return _result('online','target' if has_target else 'tunnel','online','VPN y destino interno verificados.' if has_target else 'Túnel, interfaz y rutas verificados.',False)
 if not e.ike_established:return _result('offline','ike','peer_no_response' if not e.peer_replied else 'ike_sa_missing','El gateway no responde.' if not e.peer_replied else 'No existe IKE_SA plant-ipsec.',True)
 if not e.child_installed:return _result('control_plane_up','child','child_sa_missing','Falta la CHILD_SA plant-ipsec.',True)
 if need_vip and not e.vip_ok:return _result('installed','modecfg','vip_missing','No se obtuvo la IP virtual requerida.',True)
 if not e.routes_ok or not e.xfrm_ok:return _result('installed','routes','route_or_xfrm_missing','El target no está cubierto por selectores XFRM bidireccionales.',True)
 if not e.target_ok:
  if e.traffic_out and e.traffic_in and not e.target_tcp_ok:return _result('installed','target','target_tcp_unreachable','El target responde por la VPN, pero el puerto TCP configurado no acepta conexiones.',True)
  return _result('installed','target','target_unreachable','El destino no generó tráfico de ida y vuelta por la SA.',True)
 return _result('online','target' if has_target else 'tunnel','online','SA, VIP, selectores, contadores y destino verificados.' if has_target else 'IKE, CHILD_SA, VIP y selectores XFRM verificados.',False)
def _slug(value):
 value=str(value or '')
 if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',value):raise ValueError('Slug VPN no válido.')
 return value
def _target(ip,port):
 addr=ipaddress.ip_address(str(ip));port=int(port)
 if addr.version!=4 or addr.is_unspecified or addr.is_multicast or addr.is_reserved or addr.is_loopback or addr.is_link_local or any(addr in net for net in validation_deny_networks()):raise ValueError('Destino de validación no permitido.')
 if not 1<=port<=65535:raise ValueError('Puerto de validación no válido.')
 return str(addr),port
def target_probe_spec(slug,target_ip,target_port):
 sl=_slug(slug);ip,port=_target(target_ip,target_port)
 return ['docker','exec','vpn-'+sl,'sh','-lc',f'timeout 5 bash -c "</dev/tcp/{ip}/{port}"']
def static_validation_specs(vpn,base):
 base=Path(base).resolve();sl=_slug(vpn['slug']);kind=str(vpn['vpn_type']);engine=str(vpn.get('ipsec_engine') or 'libreswan') if hasattr(vpn,'get') else str(vpn['ipsec_engine'] or 'libreswan');image=runtime_image(kind,engine) if kind=='ipsec' else runtime_image(kind)
 specs=[['docker','compose','-f',str(base/'docker-compose.yml'),'-f',str(base/f'sites/{sl}/compose.yml'),'config'],['docker','image','inspect',image]];prefix=['docker','run','--rm','--pull','never','--network','none','--read-only','--tmpfs','/run','--tmpfs','/tmp','--entrypoint','sh'];cfg=base/f'configs/{sl}'
 if kind=='ssl':specs.append(prefix+['-v',str(cfg/'openfortivpn.conf')+':/etc/openfortivpn/config:ro',image,'-lc','timeout 8 openfortivpn -c /etc/openfortivpn/config'])
 elif kind=='openvpn':specs.append(prefix+['-v',str(cfg/'client.ovpn')+':/etc/openvpn/client.ovpn:ro',image,'-lc','openvpn --config /etc/openvpn/client.ovpn --show-gateway'])
 elif kind=='pptp':specs.append(prefix+['-v',str(cfg/'ppp-options')+':/etc/ppp/options.pptp:ro','-v',str(cfg/'chap-secrets')+':/etc/ppp/chap-secrets:ro',image,'-lc','test -s /etc/ppp/chap-secrets && pppd dryrun file /etc/ppp/options.pptp'])
 elif kind=='ipsec':
  conf=str(cfg/'ipsec.conf');secrets=str(cfg/'ipsec.secrets')
  if engine=='strongswan':syntax='timeout 8 /usr/lib/ipsec/starter --nofork --debug-all';caps=[]
  elif engine=='libreswan':syntax='ipsec addconn --checkconfig';caps=[]
  else:raise ValueError('Motor IPsec no soportado.')
  specs.append(prefix[:2]+caps+prefix[2:]+['-v',conf+':/etc/ipsec.conf:ro','-v',secrets+':/etc/ipsec.secrets:ro',image,'-lc',syntax])
 else:raise ValueError('Tipo VPN no soportado.')
 return specs
def _validate_generated_files(vpn,base):
 sl=_slug(vpn['slug']);kind=str(vpn['vpn_type']);base=Path(base).resolve();root=(base/'configs'/sl).resolve()
 if base not in root.parents or not root.is_dir():return False
 def text(name,private=False):
  p=(root/name).resolve()
  if root not in p.parents or not p.is_file() or not 0<p.stat().st_size<=1024*1024:raise ValueError
  if private and p.stat().st_mode&0o077:raise ValueError
  return p.read_text(encoding='utf-8')
 try:
  compose=(base/'sites'/sl/'compose.yml').read_text(encoding='utf-8');engine=str(vpn.get('ipsec_engine') or 'libreswan');image=runtime_image(kind,engine) if kind=='ipsec' else runtime_image(kind)
  if 'container_name: vpn-'+sl not in compose or 'plantas.vpn.slug: "'+sl+'"' not in compose or 'image: '+image not in compose:return False
  if kind=='ssl':
   rows={}
   for line in text('openfortivpn.conf',True).splitlines():
    if not line.strip():continue
    if '=' not in line:return False
    k,val=(x.strip() for x in line.split('=',1))
    if k in rows or k not in {'host','port','username','password','set-dns','pppd-use-peerdns','trusted-cert'}:return False
    rows[k]=val
   return all(rows.get(k) for k in ('host','port','username','password')) and rows['port'].isdigit() and 1<=int(rows['port'])<=65535
  if kind=='openvpn':
   low='\n'+text('client.ovpn').lower()+'\n';return '\nclient\n' in low and '\nremote ' in low and not any(x in low for x in ('script-security','\nup ','\ndown ','route-up','ipchange','learn-address','client-connect','plugin ','management '))
  if kind=='pptp':
   opts=text('ppp-options');chap=text('chap-secrets',True);return all(x in opts for x in ('noauth','nodetach','defaultroute','replacedefaultroute','name ')) and len([x for x in chap.splitlines() if x.strip() and not x.lstrip().startswith('#')])==1
  if kind=='ipsec':
   conf=text('ipsec.conf');sec=text('ipsec.secrets',True);low=conf.lower();return low.count('conn plant-ipsec')==1 and bool(sec.strip()) and not any(x in low for x in ('include ','also='))
 except Exception:return False
 return False
def run_static_validation(vpn,base,runner):
 if not _validate_generated_files(vpn,base):return _result('draft','local','config_invalid','Los archivos generados no superan el preflight semántico.',False)
 specs=static_validation_specs(vpn,base);kind=str(vpn['vpn_type']);engine=str(vpn.get('ipsec_engine') or 'libreswan')
 for spec in specs:
  rc,out=_run(runner,spec,timeout=20);low=out.lower();joined=' '.join(spec);is_strong=(kind=='ipsec' and engine=='strongswan' and '/usr/lib/ipsec/starter' in joined);strong_loaded=is_strong and rc==0 and 'plant-ipsec' in low and ('starter' in low or 'charon' in low);ssl_parsed=(kind=='ssl' and 'openfortivpn -c ' in joined and rc in (1,124) and any(x in low for x in ('gateway','connect','resolve','network is unreachable')));pptp_parsed=(kind=='pptp' and rc==2 and 'no device specified and stdin is not a tty' in low and 'unrecognized option' not in low)
  bad=any(x in low for x in ('syntax error','parse error','unknown keyword','unknown option','invalid configuration','error parsing','no config named','failed to load connection','failed to load secrets','loading config failed'))
  if (rc!=0 and not ssl_parsed and not pptp_parsed) or bad or (is_strong and not strong_loaded):return _result('draft','local','config_invalid','La configuración generada no supera la validación estática.',False)
 return _result('validating','local','local_validated','Configuración e imagen validadas localmente.',False)
def _run(runner,argv,timeout=15):
 result=runner(argv,timeout=timeout)
 if not isinstance(result,tuple) or len(result)!=2:raise ValueError('Runner de validación no válido.')
 return int(result[0]),str(result[1] or '')
def _net_has(net,target):
 try:return ipaddress.ip_address(target) in ipaddress.ip_network(net,strict=False)
 except ValueError:return False
def _policy_blocks(output):
 blocks=[];cur=[]
 for line in str(output or '').splitlines():
  if line.startswith('src ') and cur:blocks.append(cur);cur=[]
  cur.append(line.strip())
 if cur:blocks.append(cur)
 return blocks
def _xfrm_binding(output,target,peer_ips=None):
 peers=set(peer_ips or ());out={};incoming={}
 for block in _policy_blocks(output):
  head=block[0] if block else '';m=re.search(r'^src\s+(\S+)\s+dst\s+(\S+)',head);body=' '.join(block).lower();dm=re.search(r'\bdir\s+(in|out|fwd)\b',body);rm=re.search(r'\breqid\s+(\d+)\b',body);tm=re.search(r'\btmpl\s+src\s+(\S+)\s+dst\s+(\S+).*?\breqid\s+(\d+)\b',body)
  if not m or not dm or not rm or not tm:continue
  reqid=int(rm.group(1));direction=dm.group(1);outer_src=tm.group(1);outer_dst=tm.group(2)
  if int(tm.group(3))!=reqid:continue
  if direction=='out' and _net_has(m.group(2),target) and (not peers or outer_dst in peers):out.setdefault(reqid,set()).add(m.group(1))
  if direction in {'in','fwd'} and _net_has(m.group(1),target) and (not peers or outer_src in peers):incoming.setdefault(reqid,set()).add(m.group(2))
 common=set(out)&set(incoming);return common,{r:out[r] for r in common}
def _xfrm_target_reqids(output,target,peer_ips=None):return _xfrm_binding(output,target,peer_ips)[0]
def _xfrm_covers_target(output,target):return bool(_xfrm_target_reqids(output,target))
def _counter_directions(text,reqids,peer_ips):
 peers=set(peer_ips or ());outbound=inbound=0
 for block in re.split(r'(?=^src\s)',str(text or ''),flags=re.M):
  head=re.search(r'^src\s+(\S+)\s+dst\s+(\S+)',block);rm=re.search(r'\breqid\s+(\d+)\b',block)
  if not head or not rm or int(rm.group(1)) not in reqids:continue
  total=sum(int(x) for x in re.findall(r'\bbytes(?:-i|-o)?\s+(\d+)',block,re.I))+sum(int(x) for x in re.findall(r'\b(\d+)\(bytes\)',block,re.I))
  if head.group(2) in peers:outbound+=total
  if head.group(1) in peers:inbound+=total
 return outbound,inbound
def _counter_for_reqids(text,reqids):
 total=0
 for block in re.split(r'(?=^src\s)',str(text or ''),flags=re.M):
  m=re.search(r'\breqid\s+(\d+)\b',block)
  if m and int(m.group(1)) in reqids:total+=sum(int(x) for x in re.findall(r'\bbytes(?:-i|-o)?\s+(\d+)',block,re.I))+sum(int(x) for x in re.findall(r'\b(\d+)\(bytes\)',block,re.I))
 return total
def _route_source(route):
 m=re.search(r'\bsrc\s+([0-9]+(?:\.[0-9]+){3})\b',str(route or ''));return m.group(1) if m else ''
def _status_binding(status,engine,peer_ips):
 conn='\n'.join(x for x in str(status or '').splitlines() if 'plant-ipsec' in x.lower());upper=conn.upper();peer_ok=bool(peer_ips) and any(p in conn for p in peer_ips)
 if engine=='strongswan':
  ike=peer_ok and any('ESTABLISHED' in x.upper() for x in conn.splitlines() if '[' in x);ids=set()
  for line in conn.splitlines():
   if 'INSTALLED' in line.upper():
    m=re.search(r'\breqid\s+(\d+)\b',line,re.I)
    if m:ids.add(int(m.group(1)))
  return ike,bool(ids),ids,conn
 ike=peer_ok and any(x in upper for x in ('STATE_MAIN_I4','STATE_AGGR_I2','STATE_V2_ESTABLISHED_IKE_SA','ISAKMP SA ESTABLISHED'))
 child=peer_ok and any(x in upper for x in ('STATE_QUICK_I2','STATE_V2_ESTABLISHED_CHILD_SA','TYPE=ESP'))
 return ike,child,set(),conn
def _counter_total(text):
 text=str(text or '');legacy=sum(int(x) for x in re.findall(r'\bbytes(?:-i|-o)?\s+(\d+)',text,re.I));blocks=sum(int(x) for x in re.findall(r'(?im)^\s*(?:RX|TX):\s+bytes[^\n]*\n\s*(\d+)',text));return legacy+blocks
def _route_uses_interface(route,interface):return bool(re.search(r'\bdev\s+'+re.escape(interface)+r'\b',str(route or ''))) and 'unreachable' not in str(route or '').lower()
def _identity(text):
 p=str(text or '').split();return tuple(p[:2]) if len(p)>=2 else ('','')
def _container_connected_networks(runner,name):
 rc,out=_run(runner,['docker','inspect','--format','{{json .NetworkSettings.Networks}}',name],timeout=10)
 if rc!=0:raise RuntimeError('No se pudo inspeccionar la red del runtime.')
 try:data=json.loads(out.strip())
 except Exception as e:raise RuntimeError('Respuesta de red Docker no válida.') from e
 if not isinstance(data,dict):raise RuntimeError('Respuesta de red Docker no válida.')
 nets=[]
 for item in data.values():
  if not isinstance(item,dict):continue
  ip=str(item.get('IPAddress') or '');prefix=item.get('IPPrefixLen');gateway=str(item.get('Gateway') or '')
  try:
   if ip and prefix is not None:nets.append(ipaddress.ip_network(f'{ip}/{int(prefix)}',strict=False))
   if gateway:nets.append(ipaddress.ip_network(gateway+'/32',strict=False))
  except (ValueError,TypeError):raise RuntimeError('Red Docker no válida.')
 return nets
def _xfrm_peer_binding(output,peer_ips=None):
 peers=set(peer_ips or ());out=set();incoming=set();local_sets={}
 for block in _policy_blocks(output):
  head=block[0] if block else '';m=re.search(r'^src\s+(\S+)\s+dst\s+(\S+)',head);body=' '.join(block).lower();dm=re.search(r'\bdir\s+(in|out|fwd)\b',body);rm=re.search(r'\breqid\s+(\d+)\b',body);tm=re.search(r'\btmpl\s+src\s+(\S+)\s+dst\s+(\S+).*?\breqid\s+(\d+)\b',body)
  if not m or not dm or not rm or not tm:continue
  reqid=int(rm.group(1));direction=dm.group(1);outer_src=tm.group(1);outer_dst=tm.group(2)
  if int(tm.group(3))!=reqid:continue
  if direction=='out' and (not peers or outer_dst in peers):out.add(reqid);local_sets.setdefault(reqid,set()).add(m.group(1))
  if direction in {'in','fwd'} and (not peers or outer_src in peers):incoming.add(reqid)
 common=out&incoming;return common,{r:local_sets.get(r,set()) for r in common}

def collect_runtime_evidence(vpn,runner):
 sl=_slug(vpn['slug']);kind=str(vpn['vpn_type']);engine=str(vpn.get('ipsec_engine') or 'libreswan');raw_ip=str(vpn.get('validation_target_ip') or '').strip();raw_port=vpn.get('validation_target_port');has_target=bool(raw_ip or raw_port not in (None,''))
 if bool(raw_ip)!=bool(raw_port not in (None,'')):raise ValueError('El target de validación está incompleto.')
 ip,port=_target(raw_ip,raw_port) if has_target else ('',0);selectors=remote_subnets(vpn)
 if has_target and (not selectors or not any(_net_has(net,ip) for net in selectors)):raise ValueError('Target fuera de selectores remotos aprobados.')
 name='vpn-'+sl;connected=_container_connected_networks(runner,name)
 if has_target and any(ipaddress.ip_address(ip) in net for net in connected):return ValidationEvidence(True,False,False,False,False,False,False,False,False,False)
 ic=['docker','inspect','--format','{{.Id}} {{.RestartCount}} {{.State.Running}} {{if (index .State "Health")}}{{index (index .State "Health") "Status"}}{{else}}none{{end}}',name];rc,ins=_run(runner,ic);ident=_identity(ins);parts=ins.split();container=rc==0 and len(parts)>=3 and parts[2].lower()=='true' and 'unhealthy' not in ins.lower();_,logs=_run(runner,['docker','logs','--since','10m',name]);status='';daemon=ike=child=False;xfrm_ok=vip_ok=True;interface='';reqids=set();peers=set();route='';route_src='';local_sets={}
 if kind=='ipsec':
  host=str(vpn.get('host') or '')
  try:peers={str(ipaddress.ip_address(host))}
  except ValueError:
   dr,dns=_run(runner,['docker','exec',name,'getent','ahostsv4',host]);peers={x.split()[0] for x in dns.splitlines() if x.split() and re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}',x.split()[0])} if dr==0 else set()
  status_rc,status=_run(runner,['docker','exec',name,'ipsec','statusall'] if engine=='strongswan' else ['docker','exec',name,'sh','-lc','ipsec status; ipsec trafficstatus']);daemon=status_rc==0;ike,status_child,status_ids,conn=_status_binding(status,engine,peers)
  _,policy=_run(runner,['docker','exec',name,'sh','-lc','ip xfrm policy']);reqids,local_sets=(_xfrm_binding(policy,ip,peers) if has_target else _xfrm_peer_binding(policy,peers));xfrm_ok=bool(reqids);child=(bool(status_ids & reqids) if engine=='strongswan' else status_child and xfrm_ok)
 else:
  interface='tun0' if kind=='openvpn' else 'ppp0';sr,status=_run(runner,['docker','exec',name,'ip','link','show',interface]);daemon=sr==0;ike=child=daemon
 if has_target:
  rr,route=_run(runner,['docker','exec',name,'sh','-lc',f'ip route get {ip}']);exists=rr==0 and bool(route.strip()) and 'unreachable' not in route.lower();route_src=_route_source(route)
  if kind=='ipsec':
   source_ok=bool(route_src) and any(_net_has(net,route_src) for r in reqids for net in local_sets.get(r,set()));routes_ok=exists and xfrm_ok and source_ok
   if str(vpn.get('modecfg') or '').lower() in {'pull','push'}:
    _,addresses=_run(runner,['docker','exec',name,'sh','-lc','ip -4 addr show']);vip_ok=bool(route_src and re.search(r'\binet\s+'+re.escape(route_src)+r'/',addresses)) and source_ok
  else:routes_ok=exists and _route_uses_interface(route,interface)
 else:
  if kind=='ipsec':
   routes_ok=xfrm_ok
   if str(vpn.get('modecfg') or '').lower() in {'pull','push'}:
    _,addresses=_run(runner,['docker','exec',name,'sh','-lc','ip -4 addr show']);assigned=set(re.findall(r'\binet\s+([0-9]+(?:\.[0-9]+){3})/',addresses));candidates=set()
    for nets in local_sets.values():
     for net in nets:
      try:
       parsed=ipaddress.ip_network(net,strict=False)
       if parsed.version==4 and parsed.prefixlen==32:candidates.add(str(parsed.network_address))
      except ValueError:pass
    vip_ok=bool(assigned & candidates)
  else:
   ar,addresses=_run(runner,['docker','exec',name,'sh','-lc',f'ip -4 addr show dev {interface}']);rr,routes=_run(runner,['docker','exec',name,'sh','-lc',f'ip -4 route show dev {interface}']);has_addr=ar==0 and bool(re.search(r'\binet\s+[0-9]+(?:\.[0-9]+){3}/',addresses));routes_ok=has_addr and rr==0 and bool(routes.strip()) and (kind!='pptp' or bool(re.search(r'(?m)^default\b',routes)))
 tr=0;traffic_out=traffic_in=False;preprobe=container and daemon and ike and child and routes_ok and xfrm_ok and vip_ok
 if has_target:
  counter=['docker','exec',name,'sh','-lc','ip -s xfrm state' if kind=='ipsec' else f'ip -s link show {interface}'];_,before=_run(runner,counter);tr=1
  if preprobe:tr,_=_run(runner,target_probe_spec(sl,ip,port),timeout=8)
  _,after=_run(runner,counter)
 else:before=after=''
 ir,ins2=_run(runner,ic);stable=ir==0 and ident==_identity(ins2)
 if has_target and kind=='ipsec':
  bo,bi=_counter_directions(before,reqids,peers);ao,ai=_counter_directions(after,reqids,peers);traffic_out=ao>bo;traffic_in=ai>bi;traffic=traffic_out and traffic_in
 elif has_target:
  traffic=_counter_total(after)>_counter_total(before);traffic_out=traffic_in=traffic
 else:traffic=True
 target_ok=preprobe and stable and (not has_target or (tr==0 and traffic))
 combined=(status+'\n'+logs).lower();auth=any(x in combined for x in ('authentication failed','auth_failed','xauth authentication failed','eap authentication failed','invalid id information'));proposal=any(x in combined for x in ('no_proposal_chosen','no proposal chosen','no acceptable proposal'));replied=ike or any(x in combined for x in ('received packet','response message','ike negotiation complete'))
 return ValidationEvidence(container,daemon,ike,child,routes_ok,xfrm_ok,target_ok,replied,auth,proposal,vip_ok,stable,has_target and tr==0,traffic_out,traffic_in)
