#!/bin/bash
set -euo pipefail
mkdir -p /run/pluto /var/run/pluto /var/lib/ipsec/nss
rm -f /var/lib/ipsec/nss/*.db 2>/dev/null || true
ipsec initnss --nssdir /var/lib/ipsec/nss >/dev/null 2>&1 || true
ip xfrm policy flush || true
ip xfrm state flush || true
/usr/libexec/ipsec/pluto --config /etc/ipsec.conf --secretsfile /etc/ipsec.secrets --nofork --stderrlog &
IPSEC_PID=$!
sleep 5
/usr/libexec/ipsec/addconn --config /etc/ipsec.conf --verbose plant-ipsec >/dev/null 2>&1 || true
ipsec auto --add plant-ipsec >/dev/null 2>&1 || true
if [[ -f /etc/haproxy/haproxy.cfg ]] && grep -Eq '^[[:space:]]*(frontend|listen)[[:space:]]+' /etc/haproxy/haproxy.cfg; then
  haproxy -c -f /etc/haproxy/haproxy.cfg
  haproxy -f /etc/haproxy/haproxy.cfg -db &
  HAPROXY_PID=$!
else
  HAPROXY_PID=''
fi
export HAPROXY_PID IPSEC_PID
export VPN_ENGINE=libreswan
export VPN_CONN_NAME=plant-ipsec
ipsec auto --up plant-ipsec >/dev/null 2>&1 &
exec /usr/local/sbin/vpn-supervisor.sh
