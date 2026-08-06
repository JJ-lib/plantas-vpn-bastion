#!/bin/sh
set -eu
BASTION_ACCESS_CIDRS="${BASTION_ACCESS_CIDRS:?BASTION_ACCESS_CIDRS is required}"
old_gw="$(ip route show default | awk 'NR==1 {print $3}')"
old_dev="$(ip route show default | awk 'NR==1 {print $5}')"
if [ -n "$old_gw" ] && [ -n "$old_dev" ]; then
  for cidr in $BASTION_ACCESS_CIDRS; do
    case "$cidr" in ''|*[!0-9./]*) exit 65 ;; esac
    ip route replace "$cidr" via "$old_gw" dev "$old_dev"
  done
fi
case "${VPN_CLIENT_TYPE:?VPN_CLIENT_TYPE is required}" in
  pptp) /etc/pptp/start-pptp.sh & client_pid=$! ;;
  openvpn) openvpn --config /etc/openvpn/client.ovpn --verb 3 & client_pid=$! ;;
  *) exit 64 ;;
esac
haproxy -W -db -f /etc/haproxy/haproxy.cfg &
haproxy_pid=$!
trap 'kill "$client_pid" "$haproxy_pid" 2>/dev/null || true; wait' INT TERM
wait "$client_pid"
