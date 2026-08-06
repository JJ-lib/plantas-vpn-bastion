#!/bin/sh
set -u
LC_ALL=C
export LC_ALL

VPN_ENGINE=${VPN_ENGINE:?VPN_ENGINE requerido}
VPN_CONN_NAME=${VPN_CONN_NAME:-plant-ipsec}
VPN_HEALTH_FILE=${VPN_HEALTH_FILE:-/run/vpn-health}
VPN_IPSEC_BIN=${VPN_IPSEC_BIN:-ipsec}
VPN_CHECK_INTERVAL=${VPN_CHECK_INTERVAL:-10}
VPN_SLEEP_BIN=${VPN_SLEEP_BIN:-sleep}
VPN_FAIL_THRESHOLD=${VPN_FAIL_THRESHOLD:-3}
VPN_BACKOFF_STEPS=${VPN_BACKOFF_STEPS:-10,30,60,120,300}
VPN_SUPERVISOR_MAX_CYCLES=${VPN_SUPERVISOR_MAX_CYCLES:-0}
HAPROXY_PID=${HAPROXY_PID:-}
IPSEC_PID=${IPSEC_PID:?IPSEC_PID requerido}

case "$VPN_ENGINE" in strongswan|libreswan) :;; *) echo "motor VPN no soportado" >&2; exit 64;; esac

log() { printf '%s %s\n' "$(TZ=Europe/Madrid date '+%Y-%m-%d %H:%M:%S %Z')" "$*"; }
write_health() {
    d=$(dirname "$VPN_HEALTH_FILE")
    mkdir -p "$d"
    t="${VPN_HEALTH_FILE}.tmp.$$"
    printf '%s\n' "$1" > "$t"
    mv -f "$t" "$VPN_HEALTH_FILE"
}
is_online() {
    if [ "$VPN_ENGINE" = strongswan ]; then
        "$VPN_IPSEC_BIN" statusall 2>/dev/null | grep -Eq "${VPN_CONN_NAME}\{[0-9]+\}:[[:space:]]+INSTALLED"
    else
        "$VPN_IPSEC_BIN" whack --trafficstatus 2>/dev/null | grep -Fq "$VPN_CONN_NAME"
    fi
}
recover_tunnel() {
    if [ "$VPN_ENGINE" = strongswan ]; then
        "$VPN_IPSEC_BIN" up "$VPN_CONN_NAME" >/dev/null 2>&1 || true
        is_online && return 0
        "$VPN_IPSEC_BIN" down "$VPN_CONN_NAME" >/dev/null 2>&1 || true
        "$VPN_IPSEC_BIN" up "$VPN_CONN_NAME" >/dev/null 2>&1 || true
        is_online
    else
        "$VPN_IPSEC_BIN" auto --up "$VPN_CONN_NAME" >/dev/null 2>&1 || true
        is_online
    fi
}
backoff_at() {
    target=$1
    remaining=$VPN_BACKOFF_STEPS
    last=300
    n=1
    while [ -n "$remaining" ]; do
        case "$remaining" in
            *,*)
                value=${remaining%%,*}
                remaining=${remaining#*,}
                ;;
            *)
                value=$remaining
                remaining=
                ;;
        esac
        last=$value
        if [ "$n" -eq "$target" ]; then
            printf '%s\n' "$value"
            return
        fi
        n=$((n+1))
    done
    printf '%s\n' "$last"
}

misses=0
cooldown=0
backoff_index=1
cycles=0
write_health degraded
while :; do
    if ! kill -0 "$IPSEC_PID" 2>/dev/null; then
        write_health offline
        log "daemon IPsec ha terminado; salida fatal del supervisor"
        exit 21
    fi
    if [ -n "$HAPROXY_PID" ] && ! kill -0 "$HAPROXY_PID" 2>/dev/null; then
        write_health offline
        log "HAProxy ha terminado; salida fatal del supervisor"
        exit 20
    fi
    if is_online; then
        write_health online
        misses=0
        cooldown=0
        backoff_index=1
    else
        misses=$((misses+1))
        if [ "$misses" -lt "$VPN_FAIL_THRESHOLD" ]; then
            write_health degraded
        else
            write_health offline
            if [ "$cooldown" -gt 0 ]; then
                cooldown=$((cooldown-VPN_CHECK_INTERVAL))
                [ "$cooldown" -lt 0 ] && cooldown=0
            else
                log "CHILD_SA ausente; recuperación interna intento $backoff_index"
                if recover_tunnel; then
                    write_health online
                    misses=0
                    cooldown=0
                    backoff_index=1
                    log "CHILD_SA recuperada sin recrear contenedor"
                else
                    cooldown=$(backoff_at "$backoff_index")
                    backoff_index=$((backoff_index+1))
                    log "recuperación pendiente; próximo intento con backoff ${cooldown}s"
                fi
            fi
        fi
    fi
    cycles=$((cycles+1))
    if [ "$VPN_SUPERVISOR_MAX_CYCLES" -gt 0 ] && [ "$cycles" -ge "$VPN_SUPERVISOR_MAX_CYCLES" ]; then exit 0; fi
    "$VPN_SLEEP_BIN" "$VPN_CHECK_INTERVAL"
done
