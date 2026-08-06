#!/bin/bash
set -euo pipefail
if [[ ! -f /etc/ipsec.conf || ! -f /etc/ipsec.secrets ]]; then echo 'ERROR: faltan archivos IPsec requeridos' >&2; exit 1; fi
mkdir -p /run/strongswan /var/run
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
rm -f /run/charon.pid /var/run/charon.pid /run/starter.charon.pid
ip xfrm policy flush || true
ip xfrm state flush || true
ipsec start --nofork &
IPSEC_PID=$!
sleep 5
if [[ -f /etc/haproxy/haproxy.cfg ]] && grep -Eq '^[[:space:]]*(frontend|listen)[[:space:]]+' /etc/haproxy/haproxy.cfg; then
  haproxy -c -f /etc/haproxy/haproxy.cfg
  haproxy -f /etc/haproxy/haproxy.cfg -db &
  HAPROXY_PID=$!
else
  HAPROXY_PID=''
fi
export HAPROXY_PID IPSEC_PID
export VPN_ENGINE=strongswan
export VPN_CONN_NAME=plant-ipsec
ipsec up plant-ipsec >/dev/null 2>&1 &
exec /usr/local/sbin/vpn-supervisor.sh
