from __future__ import annotations
import ipaddress,json
VPN_RUNTIME_IMAGES={'ssl':'sha256:a59778b533b6f71255ca202ba2ad086fdb6fa71a778944d59d2f38582faadacd','openvpn':'sha256:acee6acc6c24002743c9d1b4dfef556143fa4680f6706b5fd3e10924f129d3eb','pptp':'sha256:acee6acc6c24002743c9d1b4dfef556143fa4680f6706b5fd3e10924f129d3eb','strongswan':'sha256:4485a68977905a75386d770aa1f473d316b5b2ae808caf03e7df09034ec8e6c6','libreswan':'sha256:675e02e42aa3202468ccffbac3096d52eeea542def73c9699085a345c2444155'}
ENC={'aes128','aes192','aes256','3des'};AUTH={'sha1','sha256','sha384','sha512'}
def _get(v,key,default=''):
 try:return v.get(key,default)
 except AttributeError:
  try:return v[key]
  except (KeyError,IndexError):return default
def runtime_image(vpn_type,engine=''):
 key=engine if vpn_type=='ipsec' else vpn_type
 if key not in VPN_RUNTIME_IMAGES:raise ValueError('Runtime VPN no soportado.')
 return VPN_RUNTIME_IMAGES[key]
def _validated_rows(rows):
 if not isinstance(rows,list) or not rows:raise ValueError('Faltan propuestas criptográficas.')
 out=[]
 for row in rows:
  if not isinstance(row,dict):raise ValueError('Propuesta criptográfica no válida.')
  enc=str(row.get('encryption','')).lower();auth=str(row.get('integrity','')).lower()
  if enc not in ENC:raise ValueError('Cifrado de propuesta no soportado.')
  if auth not in AUTH:raise ValueError('Integridad de propuesta no soportada.')
  item={'encryption':enc,'integrity':auth}
  if item not in out:out.append(item)
 return out
def proposal_rows(v,phase):
 key=f'phase{phase}_proposals_json';raw=_get(v,key,'')
 if raw:
  try:return _validated_rows(json.loads(raw))
  except (TypeError,json.JSONDecodeError) as e:raise ValueError('JSON de propuestas no válido.') from e
 first={'encryption':str(_get(v,f'phase{phase}_enc','')).lower(),'integrity':str(_get(v,f'phase{phase}_auth','')).lower()};rows=[first]
 enc2=str(_get(v,f'phase{phase}_enc2','')).lower()
 if enc2:rows.append({'encryption':enc2,'integrity':str(_get(v,f'phase{phase}_auth2','')).lower()})
 return _validated_rows(rows)
def expand_ike_proposals(rows,dh_groups,dh_map):
 rows=_validated_rows(rows);groups=[]
 for group in dh_groups:
  group=str(group)
  if group not in dh_map:raise ValueError('Grupo DH no soportado.')
  if group not in groups:groups.append(group)
 if not groups:raise ValueError('Faltan grupos DH.')
 return [f"{row['encryption']}-{row['integrity']}-{dh_map[group]}" for row in rows for group in groups]
def remote_subnets(v):
 raw=_get(v,'remote_subnets_json','');values=[]
 if raw:
  try:loaded=json.loads(raw)
  except (TypeError,json.JSONDecodeError) as e:raise ValueError('JSON de redes remotas no válido.') from e
  if not isinstance(loaded,list):raise ValueError('Redes remotas no válidas.')
 else:loaded=[_get(v,'remote_subnet','0.0.0.0/0') or '0.0.0.0/0']
 for value in loaded:
  try:network=ipaddress.ip_network(str(value),strict=False)
  except ValueError as e:raise ValueError('Red remota no válida.') from e
  if network.version!=4:raise ValueError('Solo se admiten selectores IPv4.')
  normalized=str(network)
  if normalized not in values:values.append(normalized)
 if not values:values=['0.0.0.0/0']
 return values
