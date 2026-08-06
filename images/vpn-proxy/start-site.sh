#!/usr/bin/env bash
set -euo pipefail

VPN_CONFIG="${VPN_CONFIG:-/etc/openfortivpn/config}"
HAPROXY_CONFIG="${HAPROXY_CONFIG:-/etc/haproxy/haproxy.cfg}"
VPN_READY_TIMEOUT="${VPN_READY_TIMEOUT:-90}"

if [[ ! -c /dev/ppp ]]; then
  echo "ERROR: /dev/ppp no existe. Arranca el contenedor con --device /dev/ppp y cap_add NET_ADMIN." >&2
  exit 1
fi

if [[ ! -f "$VPN_CONFIG" ]]; then
  echo "ERROR: falta config VPN: $VPN_CONFIG" >&2
  exit 1
fi

if [[ ! -f "$HAPROXY_CONFIG" ]]; then
  echo "ERROR: falta config HAProxy: $HAPROXY_CONFIG" >&2
  exit 1
fi

cleanup() {
  echo "Parando procesos..."
  if [[ -n "${HAPROXY_PID:-}" ]]; then
    kill "$HAPROXY_PID" 2>/dev/null || true
  fi
  if [[ -n "${VPN_PID:-}" ]]; then
    kill "$VPN_PID" 2>/dev/null || true
  fi
  wait || true
}
trap cleanup TERM INT EXIT

echo "Iniciando openfortivpn con $VPN_CONFIG"
openfortivpn -c "$VPN_CONFIG" &
VPN_PID=$!

echo "Esperando interfaz PPP hasta ${VPN_READY_TIMEOUT}s..."
for i in $(seq 1 "$VPN_READY_TIMEOUT"); do
  if ! kill -0 "$VPN_PID" 2>/dev/null; then
    echo "ERROR: openfortivpn terminó antes de levantar la VPN" >&2
    wait "$VPN_PID" || true
    exit 1
  fi
  if ip link show | grep -qE '^[0-9]+: ppp[0-9]+'; then
    echo "VPN levantada:"
    ip -brief addr show | grep ppp || true
    break
  fi
  sleep 1
  if [[ "$i" == "$VPN_READY_TIMEOUT" ]]; then
    echo "ERROR: timeout esperando PPP" >&2
    exit 1
  fi
done

echo "Validando HAProxy"
haproxy -c -f "$HAPROXY_CONFIG"

echo "Iniciando HAProxy"
haproxy -f "$HAPROXY_CONFIG" -db &
HAPROXY_PID=$!

# Si cae VPN o HAProxy, salimos para que Docker reinicie el contenedor.
while true; do
  if ! kill -0 "$VPN_PID" 2>/dev/null; then
    echo "ERROR: openfortivpn ha caído" >&2
    exit 1
  fi
  if ! kill -0 "$HAPROXY_PID" 2>/dev/null; then
    echo "ERROR: HAProxy ha caído" >&2
    exit 1
  fi
  sleep 5
done
